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

/// Whether this sipp build has TLS compiled in (`sipp -v` banners `-TLS`).
fn sipp_supports_tls(sipp: &std::path::Path) -> bool {
    Command::new(sipp)
        .arg("-v")
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("TLS"))
}

/// Whether a sipp error log in `dir` shows the stream-client bind failure
/// (sipp binds its connect socket onto its own listening port; macOS refuses
/// with EADDRINUSE where Linux's SO_REUSEADDR semantics allow it).
fn sipp_stream_client_cannot_bind(dir: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name().to_string_lossy().ends_with("_errors.log")
            && std::fs::read_to_string(e.path())
                .is_ok_and(|s| s.contains("Unable to bind TCP socket"))
    })
}

/// Self-signed cert + key PEM files for both sides of a TLS interop run.
/// Returns the tempdir (keep alive) and the two paths.
fn tls_identity_files() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let cert_path = dir.path().join("cacert.pem");
    let key_path = dir.path().join("cakey.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    (dir, cert_path, key_path)
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

#[test]
fn tls_uac_against_real_sipp_uas() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::tls_uac_against_real_sipp_uas — no sipp binary found. \
             Set SIPP_BIN=/path/to/sipp or put sipp on PATH (docs/TESTING.md §4)."
        );
        return;
    };
    if !sipp_supports_tls(&sipp) {
        eprintln!(
            "SKIPPED interop::tls_uac_against_real_sipp_uas — this sipp build \
             has no TLS support (`sipp -v` lacks the -TLS banner)."
        );
        return;
    }
    let (_dir, cert, key) = tls_identity_files();
    let port = free_port();
    let mut sipp_proc = Reaper(
        Command::new(&sipp)
            .args([
                "-sn",
                "uas",
                "-t",
                "l1",
                "-tls_cert",
                cert.to_str().expect("utf8 path"),
                "-tls_key",
                key.to_str().expect("utf8 path"),
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
            .spawn()
            .expect("cannot spawn sipp"),
    );
    // Give the UAS a moment to bind before sipr dials its TLS connection.
    std::thread::sleep(Duration::from_millis(300));

    let mut sipr_proc = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .args([
                "-sn",
                "uac",
                "-t",
                "l1",
                "-tls_cert",
                cert.to_str().expect("utf8 path"),
                "-tls_key",
                key.to_str().expect("utf8 path"),
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
    let _ = wait_with_timeout(&mut sipp_proc.0, Duration::from_secs(10));
}

#[test]
fn real_sipp_tls_uac_against_sipr_uas() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::real_sipp_tls_uac_against_sipr_uas — no sipp binary found. \
             Set SIPP_BIN=/path/to/sipp or put sipp on PATH (docs/TESTING.md §4)."
        );
        return;
    };
    if !sipp_supports_tls(&sipp) {
        eprintln!(
            "SKIPPED interop::real_sipp_tls_uac_against_sipr_uas — this sipp build \
             has no TLS support (`sipp -v` lacks the -TLS banner)."
        );
        return;
    }
    let (_dir, cert, key) = tls_identity_files();
    let port = free_port();
    let mut sipr_uas = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .args([
                "-sn",
                "uas",
                "-t",
                "l1",
                "-tls_cert",
                cert.to_str().expect("utf8 path"),
                "-tls_key",
                key.to_str().expect("utf8 path"),
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
    // sipp's stream-transport client bind does not walk past an occupied
    // default port (unlike UDP), so hand it a known-free local port.
    let uac_port = free_port();
    let log_dir = tempfile::tempdir().expect("sipp log dir");
    let mut sipp_uac = Reaper(
        Command::new(&sipp)
            .args([
                "-sn",
                "uac",
                "-t",
                "l1",
                "-tls_cert",
                cert.to_str().expect("utf8 path"),
                "-tls_key",
                key.to_str().expect("utf8 path"),
                "-p",
                &uac_port.to_string(),
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
                "-trace_err",
                &format!("127.0.0.1:{port}"),
            ])
            .current_dir(log_dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sipp uac"),
    );
    let sipp_code = wait_with_timeout(&mut sipp_uac.0, Duration::from_secs(25));
    if sipp_code != Some(0) && sipp_stream_client_cannot_bind(log_dir.path()) {
        // sipp binds its outbound stream socket onto its own listening port;
        // macOS refuses that with EADDRINUSE where Linux allows it. An
        // environment limit of sipp's, not a sipr behavior — skip visibly.
        eprintln!(
            "SKIPPED interop::real_sipp_tls_uac_against_sipr_uas — this host's \
             sipp cannot run stream-transport client modes (its connect socket \
             bind fails with EADDRINUSE; known sipp-on-macOS limitation)."
        );
        return;
    }
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
