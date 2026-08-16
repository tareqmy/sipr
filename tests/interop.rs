//! Interop suite: sipr against a REAL SIPp binary (docs/TESTING.md §4).
//!
//! Locating sipp: `$SIPP_BIN`, then `sipp` on PATH. When neither exists the
//! tests print a VISIBLE skip marker and pass vacuously — a green run that
//! executed nothing must be distinguishable in the log (never silent).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn sipp_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SIPP_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("sipp"))
        .find(|c| c.is_file())
}

/// A free UDP port on loopback (bind-then-drop; racy in theory, fine here).
fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("addr").port()
}

/// Kill the child on drop so a failing test never leaks a sipp process.
struct Reaper(Child);

impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_with_timeout(child: &mut Child, limit: Duration) -> Option<i32> {
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return status.code();
        }
        if start.elapsed() > limit {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn uac_against_real_sipp_uas() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::uac_against_real_sipp_uas — no sipp binary found. \
             Set SIPP_BIN=/path/to/sipp or put sipp on PATH (docs/TESTING.md §4)."
        );
        return;
    };
    let port = free_port();
    let sipp_child = Command::new(&sipp)
        .args([
            "-sn",
            "uas",
            "-i",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "5",
            "-timeout",
            "30s",
            "-bg",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    // Some sipp builds daemonize with -bg; retry plain if spawn failed.
    let mut sipp_proc = match sipp_child {
        Ok(c) => Reaper(c),
        Err(e) => panic!("cannot spawn sipp: {e}"),
    };
    // Give the UAS a moment to bind.
    std::thread::sleep(Duration::from_millis(300));

    let mut sipr_proc = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .args([
                "-sn",
                "uac",
                "-i",
                "127.0.0.1",
                "-r",
                "10",
                "-m",
                "5",
                "-d",
                "100",
                "-timeout",
                "20",
                &format!("127.0.0.1:{port}"),
            ])
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipr"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_proc.0, Duration::from_secs(25));
    let stderr = sipr_proc
        .0
        .stderr
        .take()
        .map(|mut s| {
            use std::io::Read;
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            buf
        })
        .unwrap_or_default();
    assert_eq!(sipr_code, Some(0), "sipr must exit 0; stderr:\n{stderr}");
    assert!(
        stderr.contains("successful 5 failed 0"),
        "sipr summary:\n{stderr}"
    );
    // sipp with -m exits by itself once its calls complete; without -bg it
    // returns its own status. With -bg the parent exits immediately, which
    // is also fine — sipr's side already proved the flows completed.
    let _ = wait_with_timeout(&mut sipp_proc.0, Duration::from_secs(10));
}

#[test]
fn real_sipp_uac_against_sipr_uas() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::real_sipp_uac_against_sipr_uas — no sipp binary found. \
             Set SIPP_BIN=/path/to/sipp or put sipp on PATH (docs/TESTING.md §4)."
        );
        return;
    };
    let port = free_port();
    let mut sipr_uas = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "5",
                "-timeout",
                "30",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipp_uac = Reaper(
        Command::new(&sipp)
            .args([
                "-sn",
                "uac",
                "-i",
                "127.0.0.1",
                "-r",
                "10",
                "-m",
                "5",
                "-d",
                "100",
                "-timeout",
                "20s",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sipp uac"),
    );
    let sipp_code = wait_with_timeout(&mut sipp_uac.0, Duration::from_secs(25));
    assert_eq!(sipp_code, Some(0), "sipp uac must exit 0");
    let sipr_code = wait_with_timeout(&mut sipr_uas.0, Duration::from_secs(15));
    let stderr = sipr_uas
        .0
        .stderr
        .take()
        .map(|mut s| {
            use std::io::Read;
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            buf
        })
        .unwrap_or_default();
    assert_eq!(
        sipr_code,
        Some(0),
        "sipr uas must exit 0; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("successful 5 failed 0"),
        "sipr uas summary:\n{stderr}"
    );
}
