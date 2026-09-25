//! Helpers shared by the test binaries that start child processes on
//! ports they probe first: `interop.rs` and `e2e.rs`.
//!
//! cargo runs a binary's tests in parallel threads, so one test's port
//! probe can race another test's child spawn. Every probe and every spawn
//! goes through here (docs/TESTING.md §4).

// Each binary uses its own subset.
#![allow(dead_code)]

use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{PoisonError, RwLock, RwLockWriteGuard};

/// Port probes against child spawns. macOS has no `SOCK_CLOEXEC`, so std
/// creates a socket and only then sets `FD_CLOEXEC` on it: a child spawned
/// from another test thread in between inherits the socket, and once the
/// probe binds it the child holds that port for as long as it lives. The
/// process the port is then handed to cannot bind it (sipp "Unable to bind
/// main socket", sipr "cannot bind UDP socket": address in use) and what
/// the test sends there lands in a socket nobody reads. Probes hold this
/// exclusively, every spawn holds it shared (`SpawnOutsideProbes`).
static PORT_PROBES: RwLock<()> = RwLock::new(());

/// Hold off every spawn while the caller has probe sockets open.
pub fn probing() -> RwLockWriteGuard<'static, ()> {
    PORT_PROBES.write().unwrap_or_else(PoisonError::into_inner)
}

/// `spawn` and `output` that never overlap a port probe (`PORT_PROBES`).
/// Every child this suite starts goes through one of these.
pub trait SpawnOutsideProbes {
    fn spawn_outside_probes(&mut self) -> std::io::Result<Child>;
    /// `output()` with its default stdio: stdin null, stdout and stderr
    /// captured. Only the spawn waits out a probe, not the child's run.
    fn output_outside_probes(&mut self) -> std::io::Result<Output>;
}

impl SpawnOutsideProbes for Command {
    fn spawn_outside_probes(&mut self) -> std::io::Result<Child> {
        let _no_probe = PORT_PROBES.read().unwrap_or_else(PoisonError::into_inner);
        self.spawn()
    }

    fn output_outside_probes(&mut self) -> std::io::Result<Output> {
        self.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_outside_probes()?
            .wait_with_output()
    }
}

/// A free *even* UDP port with its `+2` also free (RTP conventions; SIPp's
/// echo binds both).
pub fn free_even_port() -> u16 {
    let _probing = probing();
    for _ in 0..100 {
        let base = media_port_candidate();
        let a = UdpSocket::bind(("127.0.0.1", base));
        let b = UdpSocket::bind(("127.0.0.1", base + 2));
        if a.is_ok() && b.is_ok() {
            return base;
        }
    }
    panic!("no free even port pair");
}

/// A base port with `base..base+span` all free, for `[auto_media_port]`
/// scenarios that spread calls over 4-port blocks.
pub fn free_port_block(span: u16) -> u16 {
    let _probing = probing();
    for _ in 0..100 {
        let base = media_port_candidate();
        let held: Vec<_> = (0..span)
            .map(|i| UdpSocket::bind(("127.0.0.1", base + i)))
            .collect();
        if held.iter().all(Result::is_ok) {
            return base;
        }
    }
    panic!("no free port block of {span}");
}

/// A random even port in 20000..45000 — below the OS ephemeral range
/// (49152+ on macOS), so a media port probed-then-released here is not
/// handed to some other test's socket a moment later.
fn media_port_candidate() -> u16 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let n = SEED.fetch_add(1, Ordering::Relaxed);
    let mut x =
        nanos ^ (u64::from(std::process::id()) << 32) ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 33;
    x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    x ^= x >> 29;
    #[allow(clippy::cast_possible_truncation)]
    let port = 20_000 + (x % 25_000) as u16;
    port & !1
}

/// A free loopback port that binds on *both* TCP and UDP, drawn from the
/// same below-ephemeral range as media ports. Tests hand this number to a
/// spawned sipr (`-p`, `-cp`, `--sipr-http`, `-3pcc`, ...) whose transport
/// may be TCP or TLS, so a UDP-only probe is not enough: on Windows the
/// Hyper-V/WinNAT excluded port ranges are per protocol, and a port the OS
/// happily allocated for UDP can fail a later TCP bind with error 10013.
pub fn free_port() -> u16 {
    let _probing = probing();
    for _ in 0..100 {
        let port = media_port_candidate();
        if port_binds_on_tcp_and_udp(port) {
            return port;
        }
    }
    panic!("no free TCP+UDP port");
}

/// Whether `port` can be bound on loopback for both TCP and UDP right now.
fn port_binds_on_tcp_and_udp(port: u16) -> bool {
    let addr = ("127.0.0.1", port);
    TcpListener::bind(addr).is_ok() && UdpSocket::bind(addr).is_ok()
}
