//! Ending a thread that blocks in `recv_from` or `accept`: raise its stop
//! flag, then reach the socket from outside so the call returns and the
//! thread sees the flag. Every listener owns its thread this way, so a
//! dropped transport releases its port at once instead of at process exit
//! — what an embedder starting a UAS on a port, then another, relies on.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// How long a wake-up connection may take before the thread is left to
/// end on its own (the port then frees when it does).
const WAKE_TIMEOUT: Duration = Duration::from_millis(200);

/// Where a socket bound at `local` can be reached from this host: itself,
/// or loopback when it is bound to every interface.
pub(crate) fn reachable(local: SocketAddr) -> SocketAddr {
    let ip = match local.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, local.port())
}

/// An empty datagram to a UDP socket blocked in `recv_from`.
pub(crate) fn wake_udp(local: SocketAddr) -> bool {
    let any: IpAddr = match local.ip() {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    UdpSocket::bind(SocketAddr::new(any, 0))
        .and_then(|waker| waker.send_to(&[], reachable(local)))
        .is_ok()
}

/// A connection to a listener blocked in `accept`, closed at once.
pub(crate) fn wake_tcp(local: SocketAddr) -> bool {
    TcpStream::connect_timeout(&reachable(local), WAKE_TIMEOUT).is_ok()
}

/// Raise `stop`, wake the thread with `wake`, and join it — or detach it
/// when the wake-up could not reach it, rather than wait forever.
pub(crate) fn stop_and_join(
    stop: &AtomicBool,
    thread: Option<std::thread::JoinHandle<()>>,
    wake: impl FnOnce() -> bool,
) {
    stop.store(true, Ordering::Release);
    let Some(thread) = thread else {
        return;
    };
    if wake() {
        let _ = thread.join();
    }
}
