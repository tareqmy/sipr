//! The media thread: one scheduler replaying every active pcap stream.
//!
//! Design (docs/ARCHITECTURE.md §2 as-built, plus the lessons from SIPp's
//! `send_packets.c` and gossipper's scale engine): streams do not get a
//! thread each. A single thread owns a min-heap of `(next due, stream)`
//! and sleeps until the earliest deadline or the next command, whichever
//! comes first. Each frame is sent at `start + offset` on the capture's
//! **absolute** timeline, so jitter never accumulates and a stalled stream
//! catches up in a burst — the same self-correcting scheme SIPp uses
//! (`do_sleep`), rather than a chain of relative delays.
//!
//! Sockets are ordinary UDP sockets bound to the media port (SIPp uses a
//! raw socket, which is why `play_pcap` needs root there). A capture whose
//! packets span several destination ports gets one socket per port offset,
//! bound to `local + offset` and sending to `remote + offset`, preserving
//! SIPp's relative-port mapping (RTP on `remote`, RTCP on `remote+1`). The
//! sockets are deliberately NOT `connect`ed: a connected UDP socket reports
//! the peer's ICMP port-unreachable as a send error, and a test tool must
//! keep streaming at a peer that is not listening (SIPp's raw socket never
//! sees those errors either).
//!
//! The engine never shares state with this thread: it hands over an owned
//! [`StreamSpec`] (the capture is an `Arc`) and gets [`MediaEvent`]s back
//! on a channel. Counters are atomics the engine samples once a second.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use crate::pcap::PcapStream;
use crate::rtp::{RtpSource, RtpStep};

/// What a stream sends.
#[derive(Debug)]
pub enum Source {
    /// A parsed capture (shared across calls), replayed verbatim.
    Pcap(Arc<PcapStream>),
    /// A generated RTP stream (`rtp_stream`).
    Rtp(RtpSource),
}

impl Source {
    /// Distinct destination-port offsets this source sends to.
    fn port_offsets(&self) -> Vec<u16> {
        match self {
            Self::Pcap(p) => p.port_offsets(),
            Self::Rtp(_) => vec![0],
        }
    }
}

/// Everything needed to replay one stream for one call.
#[derive(Debug)]
pub struct StreamSpec {
    /// Owning call; [`MediaPlayer::stop`] keys on it.
    pub call_id: String,
    /// Stream tag within the call (`"audio"`, `"video"`, `"image"`,
    /// `"rtp-audio"`, `"rtp-video"`). Playing a new stream with the same
    /// call and tag replaces the old one.
    pub tag: String,
    /// What to send.
    pub source: Source,
    /// Local media address (`-mi`).
    pub local_ip: IpAddr,
    /// Local media port for this stream (`[media_port]` as advertised).
    pub local_port: u16,
    /// Peer endpoint learned from its SDP.
    pub remote: SocketAddr,
    /// SRTP `(send, receive)` contexts when the call negotiated SDES keys;
    /// generated streams only (pcap replays go out as captured).
    pub srtp: Option<(crate::srtp::SrtpContext, crate::srtp::SrtpContext)>,
}

/// What the media thread reports back to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaEvent {
    /// A stream sent its last frame.
    Finished {
        /// Owning call.
        call_id: String,
        /// Stream tag.
        tag: String,
    },
    /// A send failed and the stream was abandoned (SIPp: warning + abort
    /// of that replay; the call itself continues).
    SendError {
        /// Owning call.
        call_id: String,
        /// Stream tag.
        tag: String,
        /// The OS error.
        error: String,
    },
    /// A generated RTP stream ended (finished, stopped, or replaced): its
    /// RTP-check tally (SIPp `rtpstream.cpp`: after every send, whatever
    /// came back on the socket is compared to the payload just sent).
    CheckResult {
        /// Owning call.
        call_id: String,
        /// Stream tag (`rtp-audio` / `rtp-video`).
        tag: String,
        /// Video stream (uses `-videotolerance`).
        video: bool,
        /// Packets sent.
        sent: u64,
        /// Packets whose echo was missing or differed.
        failed: u64,
        /// Bytes received on the stream's socket.
        bytes_in: u64,
    },
}

enum Cmd {
    Play(Box<Active>),
    Stop {
        call_id: String,
        tag: Option<String>,
    },
    /// Pause/resume the generated RTP streams of a call (all, or one tag).
    Pause {
        call_id: String,
        tag: Option<String>,
        paused: bool,
    },
    Shutdown,
}

/// A stream in flight: its sockets are already bound.
struct Active {
    id: u64,
    spec: StreamSpec,
    /// `(port offset, socket bound to local + offset, remote + offset)`, one
    /// per distinct `dst_port - base_port` in the capture.
    sockets: Vec<(u16, UdpSocket, SocketAddr)>,
    started: Instant,
    next_frame: usize,
    /// RTP check tally (generated streams only).
    check_sent: u64,
    check_failed: u64,
    bytes_in: u64,
}

impl Active {
    /// The check tally as an event, for generated streams.
    fn check_result(&self) -> Option<MediaEvent> {
        let Source::Rtp(rtp) = &self.spec.source else {
            return None;
        };
        Some(MediaEvent::CheckResult {
            call_id: self.spec.call_id.clone(),
            tag: self.spec.tag.clone(),
            video: rtp.is_video(),
            sent: self.check_sent,
            failed: self.check_failed,
            bytes_in: self.bytes_in,
        })
    }
}

/// Handle to the media thread. Dropping it shuts the thread down.
pub struct MediaPlayer {
    tx: Sender<Cmd>,
    packets: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    next_id: std::cell::Cell<u64>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MediaPlayer {
    /// Start the media thread; events flow to `events`.
    #[must_use]
    pub fn start(events: Sender<MediaEvent>) -> Self {
        let (tx, rx) = channel::<Cmd>();
        let packets = Arc::new(AtomicU64::new(0));
        let bytes = Arc::new(AtomicU64::new(0));
        let counters = (Arc::clone(&packets), Arc::clone(&bytes));
        let thread = std::thread::Builder::new()
            .name("sipr-media".into())
            .spawn(move || run(&rx, &events, &counters.0, &counters.1))
            .ok();
        Self {
            tx,
            packets,
            bytes,
            next_id: std::cell::Cell::new(1),
            thread,
        }
    }

    /// Bind the stream's sockets and hand it to the scheduler. Replaces any
    /// stream already playing for the same call and tag. The first frame
    /// goes out immediately.
    ///
    /// # Errors
    ///
    /// The bind error when a media socket cannot be set up (the port is in
    /// use), or `InvalidInput` when the local and remote address families
    /// differ.
    pub fn play(&self, spec: StreamSpec) -> std::io::Result<()> {
        if spec.local_ip.is_ipv4() != spec.remote.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "media address family mismatch: local {} vs remote {}",
                    spec.local_ip, spec.remote
                ),
            ));
        }
        let mut sockets = Vec::new();
        for offset in spec.source.port_offsets() {
            let local = SocketAddr::new(spec.local_ip, spec.local_port.wrapping_add(offset));
            let remote = SocketAddr::new(spec.remote.ip(), spec.remote.port().wrapping_add(offset));
            let sock = UdpSocket::bind(local)?;
            // Generated streams also read back what the peer echoes (the RTP
            // check), so they must never block on the socket.
            if matches!(spec.source, Source::Rtp(_)) {
                sock.set_nonblocking(true)?;
            }
            sockets.push((offset, sock, remote));
        }
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let active = Active {
            id,
            spec,
            sockets,
            started: Instant::now(),
            next_frame: 0,
            check_sent: 0,
            check_failed: 0,
            bytes_in: 0,
        };
        self.tx
            .send(Cmd::Play(Box::new(active)))
            .map_err(|_| std::io::Error::other("media thread is gone"))
    }

    /// Stop every stream of `call_id` (or only the `tag` one).
    pub fn stop(&self, call_id: &str, tag: Option<&str>) {
        let _ = self.tx.send(Cmd::Stop {
            call_id: call_id.to_owned(),
            tag: tag.map(ToOwned::to_owned),
        });
    }

    /// Pause or resume the generated RTP streams of `call_id` (all of them,
    /// or only the `tag` one). Pcap replays are unaffected, as in SIPp.
    pub fn set_paused(&self, call_id: &str, tag: Option<&str>, paused: bool) {
        let _ = self.tx.send(Cmd::Pause {
            call_id: call_id.to_owned(),
            tag: tag.map(ToOwned::to_owned),
            paused,
        });
    }

    /// Frames sent so far, all streams.
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets.load(Ordering::Relaxed)
    }

    /// Payload bytes sent so far, all streams.
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

impl Drop for MediaPlayer {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Shutdown);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Idle wait when nothing is scheduled; commands wake the loop earlier.
const IDLE_WAIT: Duration = Duration::from_millis(500);

fn run(rx: &Receiver<Cmd>, events: &Sender<MediaEvent>, packets: &AtomicU64, bytes: &AtomicU64) {
    let mut streams: HashMap<u64, Active> = HashMap::new();
    let mut due: BinaryHeap<Reverse<(Instant, u64)>> = BinaryHeap::new();
    loop {
        let wait = due.peek().map_or(IDLE_WAIT, |Reverse((at, _))| {
            at.saturating_duration_since(Instant::now())
        });
        match rx.recv_timeout(wait) {
            Ok(cmd) => {
                if !apply(cmd, &mut streams, &mut due, events) {
                    return;
                }
                // Coalesce a burst of commands before sending anything.
                while let Ok(cmd) = rx.try_recv() {
                    if !apply(cmd, &mut streams, &mut due, events) {
                        return;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let now = Instant::now();
        while let Some(Reverse((at, id))) = due.peek().copied() {
            if at > now {
                break;
            }
            due.pop();
            let Some(active) = streams.get_mut(&id) else {
                continue; // stopped or replaced: stale heap entry
            };
            match pump(active, now, packets, bytes) {
                Pump::Next(at) => due.push(Reverse((at, id))),
                Pump::Finished => {
                    if let Some(a) = streams.remove(&id) {
                        if let Some(check) = a.check_result() {
                            let _ = events.send(check);
                        }
                        let _ = events.send(MediaEvent::Finished {
                            call_id: a.spec.call_id,
                            tag: a.spec.tag,
                        });
                    }
                }
                Pump::Failed(error) => {
                    if let Some(a) = streams.remove(&id) {
                        if let Some(check) = a.check_result() {
                            let _ = events.send(check);
                        }
                        let _ = events.send(MediaEvent::SendError {
                            call_id: a.spec.call_id,
                            tag: a.spec.tag,
                            error,
                        });
                    }
                }
            }
        }
    }
}

/// Apply one command; `false` means shut down. Streams that end here
/// (stopped or replaced) report their RTP-check tally first.
fn apply(
    cmd: Cmd,
    streams: &mut HashMap<u64, Active>,
    due: &mut BinaryHeap<Reverse<(Instant, u64)>>,
    events: &Sender<MediaEvent>,
) -> bool {
    let retain_reporting = |streams: &mut HashMap<u64, Active>, keep: &dyn Fn(&Active) -> bool| {
        streams.retain(|_, a| {
            let k = keep(a);
            if !k && let Some(check) = a.check_result() {
                let _ = events.send(check);
            }
            k
        });
    };
    match cmd {
        Cmd::Play(active) => {
            // One stream per (call, tag): a new play replaces the old.
            let (call_id, tag) = (active.spec.call_id.clone(), active.spec.tag.clone());
            retain_reporting(streams, &|a| a.spec.call_id != call_id || a.spec.tag != tag);
            due.push(Reverse((active.started, active.id)));
            streams.insert(active.id, *active);
        }
        Cmd::Stop { call_id, tag } => {
            retain_reporting(streams, &|a| {
                a.spec.call_id != call_id || tag.as_ref().is_some_and(|t| *t != a.spec.tag)
            });
        }
        Cmd::Pause {
            call_id,
            tag,
            paused,
        } => {
            for a in streams.values_mut() {
                let selected =
                    a.spec.call_id == call_id && tag.as_ref().is_none_or(|t| *t == a.spec.tag);
                if let (true, Source::Rtp(r)) = (selected, &mut a.spec.source) {
                    r.set_paused(paused);
                }
            }
        }
        Cmd::Shutdown => {
            for a in streams.values() {
                if let Some(check) = a.check_result() {
                    let _ = events.send(check);
                }
            }
            return false;
        }
    }
    true
}

enum Pump {
    Next(Instant),
    Finished,
    Failed(String),
}

/// Send everything that is due, then report when the next packet is.
fn pump(active: &mut Active, now: Instant, packets: &AtomicU64, bytes: &AtomicU64) -> Pump {
    match &active.spec.source {
        Source::Pcap(stream) => {
            let stream = Arc::clone(stream);
            pump_pcap(active, &stream, now, packets, bytes)
        }
        Source::Rtp(_) => pump_rtp(active, now, packets, bytes),
    }
}

/// Generated RTP: packet `n` is due at `start + n * interval`, so a stall
/// catches up in a burst and cadence never drifts.
fn pump_rtp(active: &mut Active, now: Instant, packets: &AtomicU64, bytes: &AtomicU64) -> Pump {
    let Some((_, sock, remote)) = active.sockets.first() else {
        return Pump::Failed("no media socket".into());
    };
    let started = active.started;
    let srtp = &mut active.spec.srtp;
    let Source::Rtp(rtp) = &mut active.spec.source else {
        return Pump::Failed("not an RTP source".into());
    };
    let mut recv_buf = [0u8; 2048];
    loop {
        let at = started + rtp.interval() * u32::try_from(rtp.ticks()).unwrap_or(u32::MAX);
        if at > now {
            return Pump::Next(at);
        }
        match rtp.next_packet() {
            RtpStep::Done => return Pump::Finished,
            RtpStep::Silent => {}
            RtpStep::Packet(p) => match sock.send_to(
                srtp.as_mut()
                    .map_or_else(|| p.to_vec(), |(tx, _)| tx.protect(p))
                    .as_slice(),
                remote,
            ) {
                Ok(_) => {
                    packets.fetch_add(1, Ordering::Relaxed);
                    bytes.fetch_add(p.len() as u64, Ordering::Relaxed);
                    // The RTP check: drain what the peer echoed and compare
                    // the last datagram's payload to the one just sent. An
                    // echo lags a packet, so this only passes for streams
                    // whose payload is constant (SIPp's patterns).
                    active.check_sent += 1;
                    let mut echoed: Option<usize> = None;
                    while let Ok((n, _)) = sock.recv_from(&mut recv_buf) {
                        active.bytes_in += n as u64;
                        echoed = Some(n);
                    }
                    // SRTP: unprotect the echo (peer's key) before comparing
                    // plaintext payloads; an auth failure counts as a miss.
                    let matches = echoed.is_some_and(|n| match srtp.as_mut() {
                        Some((_, rx)) => rx.unprotect(&recv_buf[..n]).is_ok_and(|clear| {
                            clear.len() > 12 && p.len() > 12 && clear[12..] == p[12..]
                        }),
                        None => n > 12 && p.len() > 12 && recv_buf[12..n] == p[12..],
                    });
                    if !matches {
                        active.check_failed += 1;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Pump::Next(now + Duration::from_millis(2));
                }
                Err(e) => return Pump::Failed(e.to_string()),
            },
        }
    }
}

fn pump_pcap(
    active: &mut Active,
    stream: &PcapStream,
    now: Instant,
    packets: &AtomicU64,
    bytes: &AtomicU64,
) -> Pump {
    while let Some(frame) = stream.frames.get(active.next_frame) {
        let at = active.started + frame.offset;
        if at > now {
            return Pump::Next(at);
        }
        let offset = frame.dst_port - stream.base_port;
        let Some((_, sock, remote)) = active.sockets.iter().find(|(o, ..)| *o == offset) else {
            return Pump::Failed(format!("no socket for port offset {offset}"));
        };
        match sock.send_to(&frame.payload, remote) {
            Ok(_) => {
                packets.fetch_add(1, Ordering::Relaxed);
                bytes.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Buffer full: try again in a moment, don't drop the stream.
                return Pump::Next(now + Duration::from_millis(2));
            }
            Err(e) => return Pump::Failed(e.to_string()),
        }
        active.next_frame += 1;
    }
    Pump::Finished
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::pcap::{build, parse};

    fn listener() -> (UdpSocket, SocketAddr) {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let a = s.local_addr().unwrap();
        (s, a)
    }

    /// A base port such that both `base` and `base + 1` are free right now.
    fn adjacent_free_pair() -> u16 {
        for _ in 0..100 {
            let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
            let base = probe.local_addr().unwrap().port();
            drop(probe);
            if base == u16::MAX {
                continue;
            }
            let a = UdpSocket::bind(("127.0.0.1", base));
            let b = UdpSocket::bind(("127.0.0.1", base + 1));
            if a.is_ok() && b.is_ok() {
                return base;
            }
        }
        panic!("no adjacent free port pair found");
    }

    fn spec(call: &str, stream: Arc<PcapStream>, remote: SocketAddr) -> StreamSpec {
        StreamSpec {
            call_id: call.into(),
            tag: "audio".into(),
            source: Source::Pcap(stream),
            local_ip: "127.0.0.1".parse().unwrap(),
            local_port: 0,
            remote,
            srtp: None,
        }
    }

    #[test]
    fn frames_arrive_in_order_on_the_capture_timeline() {
        let (rx_sock, remote) = listener();
        let stream = Arc::new(parse(&build::rtp_capture(5, 20_000, 6000)).unwrap());
        let (ev_tx, ev_rx) = channel();
        let player = MediaPlayer::start(ev_tx);
        let t0 = Instant::now();
        player
            .play(spec("c1", Arc::clone(&stream), remote))
            .unwrap();
        let mut buf = [0u8; 1500];
        for i in 0..5u16 {
            let (n, _) = rx_sock.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], &stream.frames[usize::from(i)].payload[..]);
        }
        let elapsed = t0.elapsed();
        // 4 intervals of 20 ms; generous upper bound for a loaded CI box.
        assert!(elapsed >= Duration::from_millis(75), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
        assert_eq!(
            ev_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            MediaEvent::Finished {
                call_id: "c1".into(),
                tag: "audio".into()
            }
        );
        assert_eq!(player.packets_sent(), 5);
        assert_eq!(player.bytes_sent(), 5 * 20);
    }

    #[test]
    fn multi_port_capture_uses_remote_plus_offset() {
        let remote_base = adjacent_free_pair();
        let rtp_sock = UdpSocket::bind(("127.0.0.1", remote_base)).unwrap();
        let rtcp_sock = UdpSocket::bind(("127.0.0.1", remote_base + 1)).unwrap();
        let rtp_addr = rtp_sock.local_addr().unwrap();
        rtp_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        rtcp_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let p = |dst: u16, payload: &[u8]| build::Packet {
            ts_micros: 0,
            src_port: 1,
            dst_port: dst,
            payload: payload.to_vec(),
        };
        let frames = vec![
            (0, build::ethernet_ipv4_udp(&p(9000, b"rtp"))),
            (0, build::ethernet_ipv4_udp(&p(9001, b"rtcp"))),
        ];
        let stream = Arc::new(parse(&build::pcap_file(1, &frames)).unwrap());
        let (ev_tx, _ev_rx) = channel();
        let player = MediaPlayer::start(ev_tx);
        // Local port 0 for each offset would be 0 and 1: pick a real base.
        let base = adjacent_free_pair();
        let mut s = spec("c2", stream, rtp_addr);
        s.local_port = base;
        player.play(s).unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = rtp_sock.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"rtp");
        assert_eq!(from.port(), base);
        let (n, from) = rtcp_sock.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"rtcp");
        assert_eq!(from.port(), base + 1);
    }

    #[test]
    fn stop_and_replace_cancel_pending_frames() {
        let (rx_sock, remote) = listener();
        let stream = Arc::new(parse(&build::rtp_capture(50, 20_000, 6000)).unwrap());
        let (ev_tx, ev_rx) = channel();
        let player = MediaPlayer::start(ev_tx);
        player
            .play(spec("c3", Arc::clone(&stream), remote))
            .unwrap();
        let mut buf = [0u8; 64];
        rx_sock.recv_from(&mut buf).unwrap(); // first frame is immediate
        player.stop("c3", None);
        std::thread::sleep(Duration::from_millis(100));
        rx_sock
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        // Drain anything in flight from before the stop; then silence.
        while rx_sock.recv_from(&mut buf).is_ok() {}
        assert!(rx_sock.recv_from(&mut buf).is_err(), "stream kept sending");
        assert!(ev_rx.try_recv().is_err(), "no Finished after a stop");
        // Replace: a second play for the same call/tag supersedes.
        player
            .play(spec("c3", Arc::clone(&stream), remote))
            .unwrap();
        player
            .play(spec("c3", Arc::clone(&stream), remote))
            .unwrap();
        std::thread::sleep(Duration::from_millis(60));
        player.stop("c3", Some("audio"));
        // The superseded stream may or may not have sent its frame 0 before
        // being replaced, but two live streams would repeat later sequence
        // numbers. Prove exactly one stream ran after the replacement.
        let mut seen: Vec<u16> = Vec::new();
        while let Ok((n, _)) = rx_sock.recv_from(&mut buf) {
            seen.push(u16::from_be_bytes([buf[..n][2], buf[..n][3]]));
        }
        let zeros = seen.iter().filter(|s| **s == 0).count();
        assert!((1..=2).contains(&zeros), "{seen:?}");
        let mut later: Vec<u16> = seen.iter().copied().filter(|s| *s > 0).collect();
        let n = later.len();
        later.sort_unstable();
        later.dedup();
        assert_eq!(
            later.len(),
            n,
            "duplicate frames = two streams alive: {seen:?}"
        );
        assert!(
            !later.is_empty(),
            "replacement stream never advanced: {seen:?}"
        );
    }

    #[test]
    fn bind_failure_is_reported_synchronously() {
        let (_rx_sock, remote) = listener();
        let (taken, taken_addr) = listener();
        let stream = Arc::new(parse(&build::rtp_capture(1, 0, 6000)).unwrap());
        let (ev_tx, _ev_rx) = channel();
        let player = MediaPlayer::start(ev_tx);
        let mut s = spec("c4", stream, remote);
        s.local_port = taken_addr.port();
        assert!(player.play(s).is_err());
        drop(taken);
    }

    #[test]
    fn rtp_stream_paces_pauses_and_finishes() {
        use crate::rtp::{RtpParams, RtpSource};
        let (rx_sock, remote) = listener();
        let params = RtpParams {
            payload_type: 8,
            bytes_per_packet: 4,
            ms_per_packet: 20,
            ticks_per_packet: 160,
            video: false,
        };
        // 8 bytes, 4-byte packets, 3 loops → 6 packets over ~100 ms.
        let src = RtpSource::new(Arc::from(&b"abcdefgh"[..]), params, 3, 7, 0);
        let (ev_tx, ev_rx) = channel();
        let player = MediaPlayer::start(ev_tx);
        let t0 = Instant::now();
        player
            .play(StreamSpec {
                call_id: "r1".into(),
                tag: "rtp-audio".into(),
                source: Source::Rtp(src),
                local_ip: "127.0.0.1".parse().unwrap(),
                local_port: 0,
                remote,
                srtp: None,
            })
            .unwrap();
        let mut buf = [0u8; 64];
        let mut got = Vec::new();
        for _ in 0..6 {
            let (n, _) = rx_sock.recv_from(&mut buf).unwrap();
            got.push(buf[..n].to_vec());
        }
        let elapsed = t0.elapsed();
        assert!(elapsed >= Duration::from_millis(95), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
        assert_eq!(&got[0][12..], b"abcd");
        assert_eq!(&got[1][12..], b"efgh");
        assert_eq!(&got[5][12..], b"efgh");
        let seqs: Vec<u16> = got
            .iter()
            .map(|p| u16::from_be_bytes([p[2], p[3]]))
            .collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5]);
        // The check tally comes first (nothing echoed here: all 6 failed),
        // then the finish.
        let check = ev_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            matches!(
                check,
                MediaEvent::CheckResult {
                    sent: 6,
                    failed: 6,
                    video: false,
                    ..
                }
            ),
            "{check:?}"
        );
        assert!(matches!(
            ev_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            MediaEvent::Finished { .. }
        ));
        // Pause: an infinite stream goes quiet, then resumes.
        let src = RtpSource::new(Arc::from(&b"abcdefgh"[..]), params, -1, 7, 0);
        player
            .play(StreamSpec {
                call_id: "r2".into(),
                tag: "rtp-audio".into(),
                source: Source::Rtp(src),
                local_ip: "127.0.0.1".parse().unwrap(),
                local_port: 0,
                remote,
                srtp: None,
            })
            .unwrap();
        rx_sock.recv_from(&mut buf).unwrap();
        player.set_paused("r2", None, true);
        std::thread::sleep(Duration::from_millis(60));
        rx_sock
            .set_read_timeout(Some(Duration::from_millis(80)))
            .unwrap();
        while rx_sock.recv_from(&mut buf).is_ok() {}
        assert!(
            rx_sock.recv_from(&mut buf).is_err(),
            "paused stream kept sending"
        );
        player.set_paused("r2", Some("rtp-audio"), false);
        assert!(rx_sock.recv_from(&mut buf).is_ok(), "resume sent nothing");
        player.stop("r2", None);
    }

    /// The RTP check against an echo peer: a constant-payload stream sees
    /// its own packets come back (one packet late), so nearly every check
    /// passes; only the first, with nothing echoed yet, fails.
    #[test]
    fn rtp_check_passes_against_an_echo_peer() {
        use crate::echo::EchoServer;
        use crate::rtp::{RtpParams, RtpSource};
        let base = {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            (s.local_addr().unwrap().port() & !1).max(1024)
        };
        let echo = EchoServer::start("127.0.0.1".parse().unwrap(), base, 2048).unwrap();
        let remote: SocketAddr = format!("127.0.0.1:{}", echo.media_port).parse().unwrap();
        // A 100 ms packet interval: each check looks for the previous
        // packet's echo, and a loaded CI host can take more than 20 ms to
        // schedule the echo thread.
        let params = RtpParams {
            payload_type: 8,
            bytes_per_packet: 4,
            ms_per_packet: 100,
            ticks_per_packet: 800,
            video: false,
        };
        let src = RtpSource::new(Arc::from(&[0xAAu8; 4][..]), params, 8, 7, 0);
        let (ev_tx, ev_rx) = channel();
        let player = MediaPlayer::start(ev_tx);
        player
            .play(StreamSpec {
                call_id: "chk".into(),
                tag: "rtp-audio".into(),
                source: Source::Rtp(src),
                local_ip: "127.0.0.1".parse().unwrap(),
                local_port: 0,
                remote,
                srtp: None,
            })
            .unwrap();
        let check = ev_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let MediaEvent::CheckResult {
            sent,
            failed,
            bytes_in,
            ..
        } = check
        else {
            panic!("{check:?}")
        };
        assert_eq!(sent, 8);
        assert!(failed <= 2, "failed {failed} of {sent}");
        assert!(bytes_in >= 16 * 6, "bytes_in {bytes_in}");
    }

    #[test]
    fn empty_stream_finishes_immediately() {
        let (_rx_sock, remote) = listener();
        let stream = Arc::new(parse(&build::pcap_file(1, &[])).unwrap());
        let (ev_tx, ev_rx) = channel();
        let player = MediaPlayer::start(ev_tx);
        player.play(spec("c5", stream, remote)).unwrap();
        assert!(matches!(
            ev_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            MediaEvent::Finished { .. }
        ));
    }
}
