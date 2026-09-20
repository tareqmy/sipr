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

/// A free *even* UDP port with its `+2` also free (RTP conventions; SIPp's
/// echo binds both).
fn free_even_port() -> u16 {
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
fn free_port_block(span: u16) -> u16 {
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
    sipp_error_log_contains(dir, "Unable to bind TCP socket")
}

/// Whether any sipp `*_errors.log` in `dir` mentions `needle`.
fn sipp_error_log_contains(dir: &std::path::Path, needle: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name().to_string_lossy().ends_with("_errors.log")
            && std::fs::read_to_string(e.path()).is_ok_and(|s| s.contains(needle))
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

/// sipr plays a pcap at real sipp: sipp's UAS answers with SDP (`c=`/`m=audio
/// [media_port]`), and `-rtp_echo` makes it bind that port so the RTP has a
/// real listener. Proves SDP endpoint discovery against SIPp's own answer
/// format and that the replay runs alongside the signaling. sipp's own
/// `play_pcap` needs a raw socket (root), so the reverse direction is not
/// testable here.
#[test]
fn uac_pcap_against_real_sipp_uas() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::uac_pcap_against_real_sipp_uas — no sipp binary found. \
             Set SIPP_BIN=/path/to/sipp or put sipp on PATH (docs/TESTING.md §4)."
        );
        return;
    };
    let port = free_port();
    // sipp's echo binds media_port and media_port+2: pick an even base.
    let sipp_media = free_even_port();
    let sipr_media = free_port_block(12);
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let pcap_path = dir.join(format!("sipr-interop-{pid}.pcap"));
    std::fs::write(
        &pcap_path,
        sipr_media::pcap::build::rtp_capture(10, 20_000, 6000),
    )
    .expect("write pcap");
    let scenario_path = dir.join(format!("sipr-interop-{pid}.xml"));
    std::fs::write(
        &scenario_path,
        format!(
            r#"<scenario name="uac-pcap-interop">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]p[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Type: application/sdp
    Content-Length: [len]

    v=0
    o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
    s=-
    c=IN IP[media_ip_type] [media_ip]
    t=0 0
    m=audio [auto_media_port] RTP/AVP 8
    a=rtpmap:8 PCMA/8000

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]p[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <nop><action><exec play_pcap_audio="{pcap}"/></action></nop>
  <pause milliseconds="400"/>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]p[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"#,
            pcap = pcap_path.display()
        ),
    )
    .expect("write scenario");
    let mut sipp_proc = Reaper(
        Command::new(&sipp)
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-mi",
                "127.0.0.1",
                "-mp",
                &sipp_media.to_string(),
                "-rtp_echo",
                "-m",
                "3",
                "-timeout",
                "30s",
                "-bg",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_proc = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .args([
                "-sf",
                scenario_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-mp",
                &sipr_media.to_string(),
                "-r",
                "5",
                "-m",
                "3",
                "-timeout",
                "20",
                &format!("127.0.0.1:{port}"),
            ])
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipr"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_proc.0, Duration::from_secs(25));
    let _ = std::fs::remove_file(&pcap_path);
    let _ = std::fs::remove_file(&scenario_path);
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
        stderr.contains("successful 3 failed 0"),
        "sipr summary:\n{stderr}"
    );
    assert!(stderr.contains("rtp-sent 30"), "sipr summary:\n{stderr}");
    let _ = wait_with_timeout(&mut sipp_proc.0, Duration::from_secs(10));
}

/// sipr streams an endless `rtp_stream` file at real sipp (`-rtp_echo` UAS so
/// the port is live), proving the generated RTP runs alongside signaling
/// and stops with the call.
#[test]
fn uac_rtp_stream_against_real_sipp_uas() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::uac_rtp_stream_against_real_sipp_uas — no sipp binary found. \
             Set SIPP_BIN=/path/to/sipp or put sipp on PATH (docs/TESTING.md §4)."
        );
        return;
    };
    let port = free_port();
    let sipp_media = free_even_port();
    let sipr_media = free_port();
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let audio_path = dir.join(format!("sipr-interop-{pid}.g711a"));
    std::fs::write(&audio_path, vec![0xd5u8; 1600]).expect("write audio");
    let scenario_path = dir.join(format!("sipr-interop-rtp-{pid}.xml"));
    std::fs::write(
        &scenario_path,
        format!(
            r#"<scenario name="uac-rtp-stream-interop">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]s[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Type: application/sdp
    Content-Length: [len]

    v=0
    o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
    s=-
    c=IN IP[media_ip_type] [media_ip]
    t=0 0
    m=audio [rtpstream_audio_port] RTP/AVP 8
    a=rtpmap:8 PCMA/8000

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]s[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <nop><action><exec rtp_stream="{audio},-1,8"/></action></nop>
  <pause milliseconds="400"/>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]s[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"#,
            audio = audio_path.display()
        ),
    )
    .expect("write scenario");
    let mut sipp_proc = Reaper(
        Command::new(&sipp)
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-mi",
                "127.0.0.1",
                "-mp",
                &sipp_media.to_string(),
                "-rtp_echo",
                "-m",
                "2",
                "-timeout",
                "30s",
                "-bg",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_proc = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .args([
                "-sf",
                scenario_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-mp",
                &sipr_media.to_string(),
                "-r",
                "5",
                "-m",
                "2",
                "-timeout",
                "20",
                &format!("127.0.0.1:{port}"),
            ])
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipr"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_proc.0, Duration::from_secs(25));
    let _ = std::fs::remove_file(&audio_path);
    let _ = std::fs::remove_file(&scenario_path);
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
        stderr.contains("successful 2 failed 0"),
        "sipr summary:\n{stderr}"
    );
    // Two calls × ~400 ms at 20 ms per packet ≈ 40; allow for scheduling.
    let sent: u64 = stderr
        .split("rtp-sent ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!((30..=50).contains(&sent), "rtp-sent {sent}:\n{stderr}");
    let _ = wait_with_timeout(&mut sipp_proc.0, Duration::from_secs(10));
}

/// The RTP check against real sipp: `sipp -sn uas -rtp_echo` echoes sipr's
/// pattern stream back, and with a tolerance sipr judges it — exit 0 with
/// every check passed.
#[test]
fn rtpcheck_against_real_sipp_echo() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::rtpcheck_against_real_sipp_echo — no sipp binary found. \
             Set SIPP_BIN=/path/to/sipp or put sipp on PATH (docs/TESTING.md §4)."
        );
        return;
    };
    let port = free_port();
    let sipp_media = free_even_port();
    let sipr_media = free_even_port();
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let scenario_path = dir.join(format!("sipr-interop-check-{pid}.xml"));
    std::fs::write(
        &scenario_path,
        r#"<scenario name="uac-rtpcheck-interop">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]c[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Type: application/sdp
    Content-Length: [len]

    v=0
    o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
    s=-
    c=IN IP[media_ip_type] [media_ip]
    t=0 0
    m=audio [media_port] RTP/AVP 8
    a=rtpmap:8 PCMA/8000

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]c[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <nop><action><exec rtp_stream="apattern,1,8"/></action></nop>
  <pause milliseconds="500"/>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]c[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"#,
    )
    .expect("write scenario");
    let mut sipp_proc = Reaper(
        Command::new(&sipp)
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-mi",
                "127.0.0.1",
                "-mp",
                &sipp_media.to_string(),
                "-rtp_echo",
                "-m",
                "1",
                "-timeout",
                "30s",
                "-bg",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_proc = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .args([
                "-sf",
                scenario_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-mp",
                &sipr_media.to_string(),
                "-audiotolerance",
                "0.5",
                "-cp",
                "0",
                "-m",
                "1",
                "-timeout",
                "20",
                &format!("127.0.0.1:{port}"),
            ])
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipr"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_proc.0, Duration::from_secs(25));
    let _ = std::fs::remove_file(&scenario_path);
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
    assert!(stderr.contains("successful 1 failed 0"), "{stderr}");
    assert!(stderr.contains("rtpcheck 0/1 failed"), "{stderr}");
    let _ = wait_with_timeout(&mut sipp_proc.0, Duration::from_secs(10));
}

/// SRTP against real sipp: sipr offers SDES and streams a pattern under
/// AES_CM_128_HMAC_SHA1_80 at `sipp -sf pfca_uas_audio_crypto_simple.xml`
/// (SIPp's own per-call SRTP echo, 100rel/PRACK included). The proof of
/// interop is SIPp's `-srtpcheck_debug` log: every packet must authenticate
/// and decrypt there (`processIncomingPacket() rc == 0`). The echo itself
/// cannot leave a macOS sipp — its `sendto` on a connected UDP socket fails
/// with EISCONN (errno 56), a sipp-on-macOS limitation like the stream
/// client bind — so the round-trip check is asserted only where the log
/// shows the echo was sent. Needs the SIPp source tree for the scenario
/// (`$SIPP_SRC`, else the sibling checkout) and a sipp built with OpenSSL.
#[test]
fn srtp_against_real_sipp_echo() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::srtp_against_real_sipp_echo — no sipp binary found.");
        return;
    };
    let src = std::env::var("SIPP_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            PathBuf::from(home).join("development/cprojects/sipp")
        });
    let uas_xml = src.join("sipp_scenarios/pfca_uas_audio_crypto_simple.xml");
    if !uas_xml.is_file() {
        eprintln!(
            "SKIPPED interop::srtp_against_real_sipp_echo — {} not found (set SIPP_SRC).",
            uas_xml.display()
        );
        return;
    }
    let port = free_port();
    let sipp_media = free_even_port();
    let sipr_media = free_even_port();
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let scenario_path = dir.join(format!("sipr-interop-srtp-{pid}.xml"));
    std::fs::write(
        &scenario_path,
        r#"<scenario name="uac-srtp-interop">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]s[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Supported: 100rel
    Content-Type: application/sdp
    Content-Length: [len]

    v=0
    o=16001 0 0 IN IP[local_ip_type] [local_ip]
    s=-
    c=IN IP[media_ip_type] [media_ip]
    t=0 0
    m=audio [rtpstream_audio_port] RTP/AVP 0
    a=crypto:[cryptotag1audio] [cryptosuiteaescm128sha1801audio] inline:[cryptokeyparams1audio]
    a=rtpmap:0 PCMU/8000

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180"/>
  <send retrans="500"><![CDATA[
    PRACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]s[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 PRACK
    RAck: 1 1 INVITE
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]s[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <nop><action><exec rtp_stream="apattern,1,0,PCMU/8000"/></action></nop>
  <pause milliseconds="1500"/>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]s[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 3 BYE
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"#,
    )
    .expect("write scenario");
    // sipp's -srtpcheck_debug files land in its working directory.
    let sipp_dir = dir.join(format!("sipr-interop-srtp-{pid}-sipp"));
    let _ = std::fs::remove_dir_all(&sipp_dir);
    std::fs::create_dir_all(&sipp_dir).expect("sipp dir");
    let mut sipp_proc = Reaper(
        Command::new(&sipp)
            .current_dir(&sipp_dir)
            .args([
                "-sf",
                uas_xml.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-mi",
                "127.0.0.1",
                "-mp",
                &sipp_media.to_string(),
                "-srtpcheck_debug",
                "-m",
                "1",
                "-timeout",
                "30s",
                "-bg",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_proc = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .args([
                "-sf",
                scenario_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-mp",
                &sipr_media.to_string(),
                "-cp",
                "0",
                "-m",
                "1",
                "-timeout",
                "20",
                &format!("127.0.0.1:{port}"),
            ])
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipr"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_proc.0, Duration::from_secs(25));
    let _ = std::fs::remove_file(&scenario_path);
    let _ = wait_with_timeout(&mut sipp_proc.0, Duration::from_secs(10));
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
    assert!(stderr.contains("successful 1 failed 0"), "{stderr}");
    assert!(stderr.contains("rtp-sent "), "{stderr}");
    // SIPp's view of our packets.
    let mut echo_log = String::new();
    for entry in std::fs::read_dir(&sipp_dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("debugrefileaudio") {
            echo_log.push_str(&std::fs::read_to_string(entry.path()).unwrap_or_default());
        }
    }
    let _ = std::fs::remove_dir_all(&sipp_dir);
    let accepted = echo_log.matches("processIncomingPacket() rc == 0").count();
    let rejected = echo_log.matches("processIncomingPacket() rc == -").count();
    assert!(
        accepted >= 20,
        "sipp must authenticate and decrypt sipr's SRTP: {accepted} accepted, {rejected} \
         rejected; log:\n{echo_log}"
    );
    assert_eq!(rejected, 0, "sipp rejected SRTP packets:\n{echo_log}");
    if echo_log.contains("errno = 56") {
        eprintln!(
            "NOTE interop::srtp_against_real_sipp_echo — sipp decrypted {accepted} packets but \
             its echo sendto failed with EISCONN (sipp-on-macOS limitation); the round trip \
             is covered by the e2e SRTP echo peer instead."
        );
    }
}

/// SIPp's own SRTP pair with the roles swapped: real sipp plays
/// `pfca_uac_apattern_crypto_simple.xml` (SDES offer, PRACK, an audio
/// pattern under SRTP, and its RTP check) against sipr running SIPp's
/// `pfca_uas_audio_crypto_simple.xml` unchanged — `exec rtp_echo=startaudio`
/// / `updateaudio` / `stopaudio`. sipp must judge the echoed audio good
/// (exit 0, not 253) and its rtpcheck vector must show real traffic.
#[test]
fn real_sipp_srtp_uac_against_sipr_echo_server() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::real_sipp_srtp_uac_against_sipr_echo_server — no sipp binary.");
        return;
    };
    let src = std::env::var("SIPP_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            PathBuf::from(home).join("development/cprojects/sipp")
        });
    let uac_xml = src.join("sipp_scenarios/pfca_uac_apattern_crypto_simple.xml");
    let uas_xml = src.join("sipp_scenarios/pfca_uas_audio_crypto_simple.xml");
    if !uac_xml.is_file() || !uas_xml.is_file() {
        eprintln!(
            "SKIPPED interop::real_sipp_srtp_uac_against_sipr_echo_server — {} not found \
             (set SIPP_SRC).",
            uac_xml.display()
        );
        return;
    }
    let port = free_port();
    let sipp_media = free_even_port();
    let sipr_media = free_even_port();
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let sipp_dir = dir.join(format!("sipr-interop-srtp-echo-{pid}-sipp"));
    let _ = std::fs::remove_dir_all(&sipp_dir);
    std::fs::create_dir_all(&sipp_dir).expect("sipp dir");
    let mut sipr_uas = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .current_dir(&sipp_dir)
            .args([
                "-sf",
                uas_xml.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-mp",
                &sipr_media.to_string(),
                "-m",
                "1",
                "-timeout",
                "30",
                "-bg",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    // sipp's -rtpcheck_debug file lands in its working directory.
    let mut sipp_uac = Reaper(
        Command::new(&sipp)
            .current_dir(&sipp_dir)
            .args([
                "-sf",
                uac_xml.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-mi",
                "127.0.0.1",
                "-mp",
                &sipp_media.to_string(),
                "-audiotolerance",
                "0.5",
                "-rtpcheck_debug",
                "-m",
                "1",
                "-timeout",
                "20s",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp uac"),
    );
    let sipp_code = wait_with_timeout(&mut sipp_uac.0, Duration::from_secs(25));
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
    let check_log = std::fs::read_to_string(sipp_dir.join("debugafile")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&sipp_dir);
    assert_eq!(
        sipp_code,
        Some(0),
        "sipp's RTP check of sipr's SRTP echo must pass (253 = failed); sipr stderr:\n{stderr}\n\
         sipp rtpcheck log:\n{check_log}"
    );
    assert_eq!(sipr_code, Some(0), "sipr stderr:\n{stderr}");
    assert!(stderr.contains("successful 1 failed 0"), "{stderr}");
    // "----PACKET COUNTS----" is followed by the per-task counts; the first
    // task is the audio pattern sipp streamed at us.
    let sent: u64 = check_log
        .split("----PACKET COUNTS----")
        .nth(1)
        .and_then(|rest| rest.lines().nth(1))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0);
    assert!(
        sent >= 20,
        "sipp streamed only {sent} packets:\n{check_log}"
    );
}

/// SIPp's registrar recipe (docs/scenarios/actions.rst `verifyauth`), as a
/// scenario both tools can run: challenge, verify, branch to 200 or 403.
const VERIFYAUTH_UAS: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="verifyauth-registrar">
  <recv request="REGISTER"/>
  <send><![CDATA[
    SIP/2.0 401 Authorization Required
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]SIPpTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    WWW-Authenticate: Digest realm="sipr.test", nonce="47364c23432d2e131a5fb210812c", qop="auth", algorithm=MD5
    Content-Length: 0

  ]]></send>
  <recv request="REGISTER">
    <action>
      <verifyauth assign_to="authvalid" username="alice" password="secret"/>
    </action>
  </recv>
  <nop hide="true" test="authvalid" next="goodauth"/>
  <nop hide="true" next="badauth"/>
  <label id="goodauth"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]SIPpTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[local_ip]:[local_port];transport=[transport]>
    Content-Length: 0

  ]]></send>
  <nop hide="true" next="done"/>
  <label id="badauth"/>
  <send><![CDATA[
    SIP/2.0 403 Forbidden
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]SIPpTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Content-Length: 0

  ]]></send>
  <label id="done"/>
</scenario>
"#;

/// A UAC (either tool) registering with digest credentials, expecting `expect`.
fn verifyauth_uac_scenario(password: &str, expect: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="register-{password}">
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:alice@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:alice@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 1 REGISTER
    Contact: <sip:alice@[local_ip]:[local_port]>
    Content-Length: 0

  ]]></send>
  <recv response="401" auth="true"/>
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:alice@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:alice@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 2 REGISTER
    Contact: <sip:alice@[local_ip]:[local_port]>
    [authentication username=alice password={password}]
    Content-Length: 0

  ]]></send>
  <recv response="{expect}"/>
</scenario>
"#
    )
}

/// Spawn `bin` (sipp or sipr) as the registrar on `port`, then `uac_bin` with
/// `uac_xml` against it; return (uac exit, uas exit).
fn run_verifyauth_pair(
    uas_bin: &std::path::Path,
    uac_bin: &std::path::Path,
    password: &str,
    expect: u16,
    tag: &str,
) -> (Option<i32>, Option<i32>) {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let uas_path = dir.join(format!("sipr-interop-verifyauth-uas-{tag}-{pid}.xml"));
    let uac_path = dir.join(format!("sipr-interop-verifyauth-uac-{tag}-{pid}.xml"));
    std::fs::write(&uas_path, VERIFYAUTH_UAS).expect("write uas");
    std::fs::write(&uac_path, verifyauth_uac_scenario(password, expect)).expect("write uac");
    let port = free_port();
    let mut uas = Reaper(
        Command::new(uas_bin)
            .current_dir(&dir)
            .args([
                "-sf",
                uas_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "1",
                "-timeout",
                "20",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut uac = Reaper(
        Command::new(uac_bin)
            .current_dir(&dir)
            .args([
                "-sf",
                uac_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-m",
                "1",
                "-timeout",
                "10",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uac"),
    );
    let uac_code = wait_with_timeout(&mut uac.0, Duration::from_secs(15));
    let uas_code = wait_with_timeout(&mut uas.0, Duration::from_secs(15));
    let _ = std::fs::remove_file(&uas_path);
    let _ = std::fs::remove_file(&uac_path);
    (uac_code, uas_code)
}

/// sipr's `<verifyauth>` judges real sipp's `[authentication]` header: the
/// right password reaches 200, a wrong one 403.
#[test]
fn sipr_verifyauth_judges_real_sipp_credentials() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::sipr_verifyauth_judges_real_sipp_credentials — no sipp.");
        return;
    };
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let (uac, uas) = run_verifyauth_pair(&sipr, &sipp, "secret", 200, "sipr-uas-good");
    assert_eq!(
        uac,
        Some(0),
        "sipp uac with the right password must get 200"
    );
    assert_eq!(uas, Some(0), "sipr registrar");
    let (uac, uas) = run_verifyauth_pair(&sipr, &sipp, "wrong", 403, "sipr-uas-bad");
    assert_eq!(uac, Some(0), "sipp uac with a wrong password must get 403");
    assert_eq!(uas, Some(0), "sipr registrar");
}

/// The mirror image: real sipp's `<verifyauth>` judges sipr's header.
#[test]
fn real_sipp_verifyauth_judges_sipr_credentials() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::real_sipp_verifyauth_judges_sipr_credentials — no sipp.");
        return;
    };
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let (uac, uas) = run_verifyauth_pair(&sipp, &sipr, "secret", 200, "sipp-uas-good");
    assert_eq!(
        uac,
        Some(0),
        "sipr uac with the right password must get 200 from sipp"
    );
    assert_eq!(uas, Some(0), "sipp registrar");
    let (uac, uas) = run_verifyauth_pair(&sipp, &sipr, "wrong", 403, "sipp-uas-bad");
    assert_eq!(
        uac,
        Some(0),
        "sipr uac with a wrong password must get 403 from sipp"
    );
    assert_eq!(uas, Some(0), "sipp registrar");
}

/// The corpus `_unexp.main` handler scenario (pauserestore, jump variable=,
/// closecon), with the XML declaration sipp insists on.
fn unexp_handler_uas_xml() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/crates/sipr-scenario/tests/corpus/positive/unexp_handler.xml"
    ))
    .expect("corpus")
}

/// A UAC that sends an INFO during the UAS's pause and expects its BYE
/// within `bye_timeout_ms` (see the e2e twin for the timing argument).
fn info_during_pause_uac_xml(bye_timeout_ms: u32) -> String {
    format!(
        r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="uac-info-during-pause">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <pause milliseconds="500"/>
  <send retrans="500"><![CDATA[
    INFO sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 INFO
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <recv request="BYE" timeout="{bye_timeout_ms}"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:]
    [last_Call-ID:]
    [last_CSeq:]
    Content-Length: 0

  ]]></send>
</scenario>
"#
    )
}

/// Run `uas_bin` on the handler scenario and `uac_bin` on the INFO scenario
/// against it; return (uac exit, uas exit, wall time of the UAC).
fn run_unexp_pair(
    uas_bin: &std::path::Path,
    uac_bin: &std::path::Path,
    tag: &str,
) -> (Option<i32>, Option<i32>, Duration) {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let uas_path = dir.join(format!("sipr-interop-unexp-uas-{tag}-{pid}.xml"));
    let uac_path = dir.join(format!("sipr-interop-unexp-uac-{tag}-{pid}.xml"));
    std::fs::write(&uas_path, unexp_handler_uas_xml()).expect("write uas");
    std::fs::write(&uac_path, info_during_pause_uac_xml(2800)).expect("write uac");
    let port = free_port();
    let mut uas = Reaper(
        Command::new(uas_bin)
            .current_dir(&dir)
            .args([
                "-sf",
                uas_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "1",
                "-timeout",
                "20",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let started = std::time::Instant::now();
    let mut uac = Reaper(
        Command::new(uac_bin)
            .current_dir(&dir)
            .args([
                "-sf",
                uac_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-m",
                "1",
                "-timeout",
                "15",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uac"),
    );
    let uac_code = wait_with_timeout(&mut uac.0, Duration::from_secs(20));
    let elapsed = started.elapsed();
    let uas_code = wait_with_timeout(&mut uas.0, Duration::from_secs(15));
    let _ = std::fs::remove_file(&uas_path);
    let _ = std::fs::remove_file(&uac_path);
    (uac_code, uas_code, elapsed)
}

/// sipr plays SIPp's `_unexp.main` recipe as the UAS: real sipp's INFO in
/// the middle of the pause is answered and the pause resumes where it was.
#[test]
fn sipr_unexp_handler_against_real_sipp_uac() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::sipr_unexp_handler_against_real_sipp_uac — no sipp.");
        return;
    };
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let (uac, uas, elapsed) = run_unexp_pair(&sipr, &sipp, "sipr-uas");
    assert_eq!(
        uac,
        Some(0),
        "sipp uac must get its INFO answered and the BYE in time"
    );
    assert_eq!(uas, Some(0), "sipr uas");
    assert!(
        elapsed >= Duration::from_millis(2900),
        "pause cut short: {elapsed:?}"
    );
}

/// The mirror: real sipp runs the same handler scenario against sipr's INFO,
/// pinning the recipe's semantics (retaddr, pausedaddr, restore) to SIPp's.
#[test]
fn real_sipp_unexp_handler_against_sipr_uac() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::real_sipp_unexp_handler_against_sipr_uac — no sipp.");
        return;
    };
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let (uac, uas, elapsed) = run_unexp_pair(&sipp, &sipr, "sipp-uas");
    assert_eq!(
        uac,
        Some(0),
        "sipr uac must get its INFO answered and sipp's BYE in time"
    );
    assert_eq!(uas, Some(0), "sipp uas");
    assert!(
        elapsed >= Duration::from_millis(2900),
        "pause cut short: {elapsed:?}"
    );
}

/// Run sipr's embedded UAC in transport `mode` against real sipp's embedded
/// UAS in `sipp_mode`; return (sipr exit, sipp exit, sipr stderr).
fn sipr_uac_vs_sipp_uas(
    mode: &str,
    sipp_mode: &str,
    calls: u32,
) -> (Option<i32>, Option<i32>, String) {
    let sipp = sipp_bin().expect("caller checked");
    let port = free_port();
    let dir = std::env::temp_dir();
    let mut sipp_uas = Reaper(
        Command::new(&sipp)
            .current_dir(&dir)
            .args([
                "-sn",
                "uas",
                "-t",
                sipp_mode,
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                &calls.to_string(),
                "-timeout",
                "30",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_uac = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .args([
                "-sn",
                "uac",
                "-t",
                mode,
                "-i",
                "127.0.0.1",
                "-r",
                "10",
                "-m",
                &calls.to_string(),
                "-d",
                "200",
                "-timeout",
                "20",
                "-bg",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sipr uac"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_uac.0, Duration::from_secs(25));
    let stderr = sipr_uac
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
    let sipp_code = wait_with_timeout(&mut sipp_uas.0, Duration::from_secs(15));
    (sipr_code, sipp_code, stderr)
}

/// `-t un` and `-t tn`: sipr's per-call sockets and connections against
/// real sipp's mono-socket UAS — every call completes on both sides.
#[test]
fn sipr_per_call_sockets_against_real_sipp_uas() {
    if sipp_bin().is_none() {
        eprintln!("SKIPPED interop::sipr_per_call_sockets_against_real_sipp_uas — no sipp.");
        return;
    }
    for (mode, sipp_mode) in [("un", "u1"), ("tn", "t1")] {
        let (sipr_code, sipp_code, stderr) = sipr_uac_vs_sipp_uas(mode, sipp_mode, 3);
        assert_eq!(sipr_code, Some(0), "-t {mode}: sipr stderr:\n{stderr}");
        assert!(
            stderr.contains("successful 3 failed 0"),
            "-t {mode}: {stderr}"
        );
        // Real sipp's UAS keeps each call in a 4 s timewait after the final
        // 200; under `tn` sipr closes the per-call connection as soon as its
        // call ends, and sipp (on Linux, promptly) books that call as
        // "TCP closed" — exit 1 with every call otherwise complete. sipr's
        // side, asserted above, is what this test is about.
        assert!(
            matches!(sipp_code, Some(0 | 1)),
            "-t {mode}: sipp uas exited {sipp_code:?}"
        );
    }
}

/// The mirror: real sipp's `-t un` / `-t tn` UAC against sipr's UAS — each
/// call arrives from its own socket/connection and is answered on it.
#[test]
fn real_sipp_per_call_uac_against_sipr_uas() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::real_sipp_per_call_uac_against_sipr_uas — no sipp.");
        return;
    };
    for (sipp_mode, sipr_mode) in [("un", "u1"), ("tn", "t1")] {
        let port = free_port();
        let dir = tempfile::tempdir().expect("tempdir");
        let mut sipr_uas = Reaper(
            Command::new(env!("CARGO_BIN_EXE_sipr"))
                .args([
                    "-sn",
                    "uas",
                    "-t",
                    sipr_mode,
                    "-i",
                    "127.0.0.1",
                    "-p",
                    &port.to_string(),
                    "-m",
                    "3",
                    "-timeout",
                    "30",
                    "-bg",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn sipr uas"),
        );
        std::thread::sleep(Duration::from_millis(300));
        let mut sipp_uac = Reaper(
            Command::new(&sipp)
                .current_dir(dir.path())
                .args([
                    "-sn",
                    "uac",
                    "-t",
                    sipp_mode,
                    "-i",
                    "127.0.0.1",
                    "-r",
                    "10",
                    "-m",
                    "3",
                    "-d",
                    "200",
                    "-timeout",
                    "20",
                    "-trace_err",
                    &format!("127.0.0.1:{port}"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn sipp uac"),
        );
        let sipp_code = wait_with_timeout(&mut sipp_uac.0, Duration::from_secs(25));
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
        if sipp_code != Some(0) && sipp_stream_client_cannot_bind(dir.path()) {
            eprintln!(
                "SKIPPED interop::real_sipp_per_call_uac_against_sipr_uas (-t {sipp_mode}) — \
                 sipp-on-macOS stream-client bind limitation (docs/TESTING.md)."
            );
            continue;
        }
        assert_eq!(
            sipp_code,
            Some(0),
            "sipp -t {sipp_mode} uac; sipr stderr:\n{stderr}"
        );
        assert_eq!(sipr_code, Some(0), "sipr uas; stderr:\n{stderr}");
        assert!(stderr.contains("successful 3 failed 0"), "{stderr}");
    }
}

/// `-rsa` against real sipp, three ways: sipr's UAC sends to sipp's UAS via
/// `-rsa` with a dead nominal target; sipp's UAC does the same towards
/// sipr's UAS; and sipp's UAS answers sipr's UAC through `-rsa` from a
/// socket of its own, which sipr must accept.
#[test]
fn rsa_both_ways_against_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::rsa_both_ways_against_real_sipp — no sipp.");
        return;
    };
    let dir = std::env::temp_dir();
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let spawn = |bin: &std::path::Path, args: &[&str]| {
        Reaper(
            Command::new(bin)
                .current_dir(&dir)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn"),
        )
    };
    // 1. sipr UAC -rsa → sipp UAS.
    let sipp_port = free_port();
    let dead = free_port();
    let mut uas = spawn(
        &sipp,
        &[
            "-sn",
            "uas",
            "-i",
            "127.0.0.1",
            "-p",
            &sipp_port.to_string(),
            "-m",
            "2",
            "-timeout",
            "20",
        ],
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut uac = spawn(
        &sipr,
        &[
            "-sn",
            "uac",
            "-rsa",
            &format!("127.0.0.1:{sipp_port}"),
            "-i",
            "127.0.0.1",
            "-m",
            "2",
            "-d",
            "100",
            "-timeout",
            "10",
            "-bg",
            &format!("127.0.0.1:{dead}"),
        ],
    );
    assert_eq!(
        wait_with_timeout(&mut uac.0, Duration::from_secs(15)),
        Some(0),
        "sipr uac -rsa"
    );
    assert_eq!(
        wait_with_timeout(&mut uas.0, Duration::from_secs(10)),
        Some(0),
        "sipp uas"
    );
    // 2. sipp UAC -rsa → sipr UAS.
    let sipr_port = free_port();
    let dead = free_port();
    let mut uas = spawn(
        &sipr,
        &[
            "-sn",
            "uas",
            "-i",
            "127.0.0.1",
            "-p",
            &sipr_port.to_string(),
            "-m",
            "2",
            "-timeout",
            "20",
            "-bg",
        ],
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut uac = spawn(
        &sipp,
        &[
            "-sn",
            "uac",
            "-rsa",
            &format!("127.0.0.1:{sipr_port}"),
            "-i",
            "127.0.0.1",
            "-m",
            "2",
            "-d",
            "100",
            "-timeout",
            "10",
            &format!("127.0.0.1:{dead}"),
        ],
    );
    assert_eq!(
        wait_with_timeout(&mut uac.0, Duration::from_secs(15)),
        Some(0),
        "sipp uac -rsa"
    );
    assert_eq!(
        wait_with_timeout(&mut uas.0, Duration::from_secs(10)),
        Some(0),
        "sipr uas"
    );
    // 3. sipp UAS -rsa (answers from its own socket towards sipr's port) ← sipr UAC.
    let sipp_port = free_port();
    let sipr_port = free_port();
    let mut uas = spawn(
        &sipp,
        &[
            "-sn",
            "uas",
            "-rsa",
            &format!("127.0.0.1:{sipr_port}"),
            "-i",
            "127.0.0.1",
            "-p",
            &sipp_port.to_string(),
            "-m",
            "2",
            "-timeout",
            "20",
        ],
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut uac = spawn(
        &sipr,
        &[
            "-sn",
            "uac",
            "-i",
            "127.0.0.1",
            "-p",
            &sipr_port.to_string(),
            "-m",
            "2",
            "-d",
            "100",
            "-timeout",
            "10",
            "-bg",
            &format!("127.0.0.1:{sipp_port}"),
        ],
    );
    assert_eq!(
        wait_with_timeout(&mut uac.0, Duration::from_secs(15)),
        Some(0),
        "sipr uac must accept sipp's rsa'd responses"
    );
    assert_eq!(
        wait_with_timeout(&mut uas.0, Duration::from_secs(10)),
        Some(0),
        "sipp uas -rsa"
    );
}

/// Run a UAS binary on `port` for the first call, kill it (its connection
/// goes with it) between call one and call two, and start a second one
/// while `uac_bin` places three calls over TCP a second apart with a
/// reconnection budget; return the UAC's exit code and stderr. `cwd`
/// receives sipp's trace files. `kill_when` is a UAC stderr substring that
/// times the kill (sipr's live line after call one); `None` = fixed delay.
fn tcp_reconnect_pair(
    uas_bin: &std::path::Path,
    uas_extra: &[&str],
    uac_bin: &std::path::Path,
    uac_extra: &[&str],
    kill_when: Option<&str>,
    cwd: &std::path::Path,
) -> (Option<i32>, String) {
    let port = free_port();
    let spawn_uas = || {
        let p = port.to_string();
        let mut args = vec![
            "-sn",
            "uas",
            "-t",
            "t1",
            "-i",
            "127.0.0.1",
            "-p",
            &p,
            "-m",
            "1",
            "-timeout",
            "15",
        ];
        args.extend_from_slice(uas_extra);
        Reaper(
            Command::new(uas_bin)
                .current_dir(cwd)
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn uas"),
        )
    };
    let mut first = spawn_uas();
    std::thread::sleep(Duration::from_millis(400));
    let target = format!("127.0.0.1:{port}");
    let mut args = vec![
        "-sn",
        "uac",
        "-t",
        "t1",
        "-i",
        "127.0.0.1",
        "-r",
        "1",
        "-m",
        "3",
        "-d",
        "200",
        "-timeout",
        "15",
        "-max_reconnect",
        "5",
        "-reconnect_sleep",
        "300",
    ];
    args.extend_from_slice(uac_extra);
    args.push(&target);
    let mut uac = Reaper(
        Command::new(uac_bin)
            .current_dir(cwd)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uac"),
    );
    let stderr_pipe = uac.0.stderr.take().expect("stderr");
    let (seen_tx, seen_rx) = std::sync::mpsc::channel::<()>();
    let marker = kill_when.map(str::to_owned);
    let reader = std::thread::spawn(move || {
        use std::io::BufRead;
        let mut all = String::new();
        for line in std::io::BufReader::new(stderr_pipe)
            .lines()
            .map_while(Result::ok)
        {
            if marker.as_deref().is_some_and(|m| line.contains(m)) {
                let _ = seen_tx.send(());
            }
            all.push_str(&line);
            all.push('\n');
        }
        all
    });
    // Kill the first UAS between call one and call two: when the UAC's
    // stderr shows `kill_when` (sipr's live line after call one), else after
    // a fixed delay (sipp, whose first call is at t=0 and the next at 1 s).
    match kill_when {
        Some(_) => {
            let _ = seen_rx.recv_timeout(Duration::from_secs(8));
        }
        None => std::thread::sleep(Duration::from_millis(600)),
    }
    let _ = first.0.kill();
    let _ = first.0.wait();
    let mut second = spawn_uas();
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(20));
    let stderr = reader.join().unwrap_or_default();
    let _ = wait_with_timeout(&mut second.0, Duration::from_secs(10));
    (code, stderr)
}

/// sipr's TCP UAC survives real sipp closing the connection: sipp's UAS
/// exits after call one, a second sipp UAS comes up; sipr's second call
/// finds the socket dead and fails (SIPp's order), the reset re-dials
/// (`-max_reconnect`), and the third call completes.
#[test]
fn sipr_tcp_uac_reconnects_to_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::sipr_tcp_uac_reconnects_to_real_sipp — no sipp.");
        return;
    };
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let dir = tempfile::tempdir().expect("tempdir");
    let (code, stderr) = tcp_reconnect_pair(
        &sipp,
        &[],
        &sipr,
        &["-bg", "-rp", "2000"],
        Some(" ok 1 failed 0"),
        dir.path(),
    );
    assert_eq!(
        code,
        Some(1),
        "sipr uac stderr:
{stderr}"
    );
    assert!(stderr.contains("successful 2 failed 1"), "{stderr}");
    assert!(
        stderr.contains("socket required a reconnection"),
        "{stderr}"
    );
}

/// The mirror: real sipp's TCP UAC with a reconnection budget across two
/// sipr UAS lifetimes — its second call dies on the dead socket, the third
/// completes on the re-dialed one (exit 1: one failed call, no fatal).
#[test]
fn real_sipp_tcp_uac_reconnects_to_sipr() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::real_sipp_tcp_uac_reconnects_to_sipr — no sipp.");
        return;
    };
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let dir = tempfile::tempdir().expect("tempdir");
    let (code, _) = tcp_reconnect_pair(&sipr, &["-bg"], &sipp, &["-trace_err"], None, dir.path());
    if code != Some(0) && sipp_stream_client_cannot_bind(dir.path()) {
        eprintln!("SKIPPED interop::real_sipp_tcp_uac_reconnects_to_sipr — sipp bind limitation.");
        return;
    }
    assert_eq!(
        code,
        Some(1),
        "sipp uac: one call dies on the dead socket, the rest complete"
    );
}

/// A second local IPv4 address for the per-IP socket tests (`None` on a
/// loopback-only host).
fn second_local_ipv4() -> Option<std::net::Ipv4Addr> {
    let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("10.255.255.255:9").ok()?;
    match probe.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => {
            UdpSocket::bind((v4, 0)).ok().map(|_| v4)
        }
        _ => None,
    }
}

/// `-t ui` against real sipp, both roles each way: an injection file with
/// loopback and the LAN address; the `ui` side sends from / listens on
/// both, the other side is a plain `u1` peer. Every call must complete.
#[test]
fn per_ip_sockets_both_ways_against_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::per_ip_sockets_both_ways_against_real_sipp — no sipp.");
        return;
    };
    let Some(lan) = second_local_ipv4() else {
        eprintln!(
            "SKIPPED interop::per_ip_sockets_both_ways_against_real_sipp — no second local IPv4."
        );
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let inf = dir.path().join("ips.csv");
    std::fs::write(&inf, format!("SEQUENTIAL\n127.0.0.1\n{lan}\n")).expect("write inf");
    let inf = inf.to_str().expect("utf8").to_owned();
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let spawn = |bin: &std::path::Path, args: &[&str]| {
        Reaper(
            Command::new(bin)
                .current_dir(dir.path())
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn"),
        )
    };
    let ui = |extra: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = vec![
            "-t".into(),
            "ui".into(),
            "-inf".into(),
            inf.clone(),
            "-ip_field".into(),
            "0".into(),
        ];
        v.extend(extra.iter().map(|s| (*s).to_owned()));
        v
    };
    // 1. sipr ui UAC → sipp u1 UAS; 2. sipp ui UAC → sipr u1 UAS.
    for (uac_bin, uas_bin, uac_bg, uas_bg) in
        [(&sipr, &sipp, true, false), (&sipp, &sipr, false, true)]
    {
        let port = free_port();
        let p = port.to_string();
        let mut uas_args: Vec<&str> = vec![
            "-sn",
            "uas",
            "-i",
            "127.0.0.1",
            "-p",
            &p,
            "-m",
            "4",
            "-timeout",
            "20",
        ];
        if uas_bg {
            uas_args.push("-bg");
        }
        let mut uas = spawn(uas_bin, &uas_args);
        std::thread::sleep(Duration::from_millis(400));
        let target = format!("127.0.0.1:{port}");
        let mut uac_args = ui(&[
            "-sn",
            "uac",
            "-i",
            "127.0.0.1",
            "-r",
            "10",
            "-m",
            "4",
            "-d",
            "100",
            "-timeout",
            "10",
        ]);
        if uac_bg {
            uac_args.push("-bg".into());
        }
        uac_args.push(target);
        let uac_refs: Vec<&str> = uac_args.iter().map(String::as_str).collect();
        let mut uac = spawn(uac_bin, &uac_refs);
        assert_eq!(
            wait_with_timeout(&mut uac.0, Duration::from_secs(15)),
            Some(0),
            "ui uac {}",
            uac_bin.display()
        );
        assert_eq!(
            wait_with_timeout(&mut uas.0, Duration::from_secs(10)),
            Some(0),
            "u1 uas {}",
            uas_bin.display()
        );
    }
    // 3. sipp ui UAS (bound on both IPs) ← sipr u1 UAC aimed at the LAN IP;
    // 4. sipr ui UAS ← sipp u1 UAC aimed at the LAN IP.
    for (uas_bin, uac_bin, uas_bg, uac_bg) in
        [(&sipp, &sipr, false, true), (&sipr, &sipp, true, false)]
    {
        let port = free_port();
        let p = port.to_string();
        let mut uas_args = ui(&[
            "-sn",
            "uas",
            "-p",
            &p,
            "-m",
            "2",
            "-timeout",
            "20",
            "-trace_err",
        ]);
        if uas_bg {
            uas_args.push("-bg".into());
        }
        let uas_refs: Vec<&str> = uas_args.iter().map(String::as_str).collect();
        let mut uas = spawn(uas_bin, &uas_refs);
        std::thread::sleep(Duration::from_millis(400));
        // sipp's own -t ui UAS fails to bind on macOS ("Address family not
        // supported by protocol family", errno 47): a sipp limitation, skip.
        if !uas_bg && sipp_error_log_contains(dir.path(), "Unable to bind main socket") {
            eprintln!(
                "SKIPPED interop::per_ip_sockets_both_ways_against_real_sipp (sipp -t ui UAS) — \
                 sipp cannot bind its per-IP main socket on this host."
            );
            continue;
        }
        let target = format!("{lan}:{port}");
        let mut uac_args: Vec<&str> = vec![
            "-sn",
            "uac",
            "-i",
            "127.0.0.1",
            "-r",
            "10",
            "-m",
            "2",
            "-d",
            "100",
            "-timeout",
            "10",
        ];
        if uac_bg {
            uac_args.push("-bg");
        }
        uac_args.push(&target);
        let mut uac = spawn(uac_bin, &uac_args);
        assert_eq!(
            wait_with_timeout(&mut uac.0, Duration::from_secs(15)),
            Some(0),
            "u1 uac {} → ui uas on the LAN IP",
            uac_bin.display()
        );
        assert_eq!(
            wait_with_timeout(&mut uas.0, Duration::from_secs(10)),
            Some(0),
            "ui uas {}",
            uas_bin.display()
        );
    }
}

/// `-t s1` against a real sipp built with SCTP (`sipp -v` banners `-SCTP`),
/// both directions; skips without such a sipp or without an SCTP stack.
#[cfg(feature = "sctp")]
#[test]
fn sctp_both_ways_against_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::sctp_both_ways_against_real_sipp — no sipp.");
        return;
    };
    let banner = Command::new(&sipp)
        .arg("-v")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if !banner.contains("SCTP") || !sipr_net::sctp::available() {
        eprintln!(
            "SKIPPED interop::sctp_both_ways_against_real_sipp — sipp without SCTP or no SCTP stack."
        );
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let spawn = |bin: &std::path::Path, args: &[&str]| {
        Reaper(
            Command::new(bin)
                .current_dir(dir.path())
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn"),
        )
    };
    for (uas_bin, uac_bin, uas_bg, uac_bg) in
        [(&sipp, &sipr, false, true), (&sipr, &sipp, true, false)]
    {
        let port = free_port();
        let p = port.to_string();
        let mut uas_args: Vec<&str> = vec![
            "-sn",
            "uas",
            "-t",
            "s1",
            "-i",
            "127.0.0.1",
            "-p",
            &p,
            "-m",
            "2",
            "-timeout",
            "20",
        ];
        if uas_bg {
            uas_args.push("-bg");
        }
        let mut uas = spawn(uas_bin, &uas_args);
        std::thread::sleep(Duration::from_millis(500));
        let target = format!("127.0.0.1:{port}");
        let mut uac_args: Vec<&str> = vec![
            "-sn",
            "uac",
            "-t",
            "s1",
            "-i",
            "127.0.0.1",
            "-r",
            "10",
            "-m",
            "2",
            "-d",
            "100",
            "-timeout",
            "10",
        ];
        if uac_bg {
            uac_args.push("-bg");
        }
        uac_args.push(&target);
        let mut uac = spawn(uac_bin, &uac_args);
        assert_eq!(
            wait_with_timeout(&mut uac.0, Duration::from_secs(15)),
            Some(0),
            "sctp uac {}",
            uac_bin.display()
        );
        assert_eq!(
            wait_with_timeout(&mut uas.0, Duration::from_secs(10)),
            Some(0),
            "sctp uas {}",
            uas_bin.display()
        );
    }
}

// ---- out-of-call scenarios (M33) -------------------------------------------

/// A UAS flow that, once the call is up, fires an OPTIONS with a fresh
/// Call-ID at its peer — an out-of-call request for the peer's `-oocsn`
/// scenario to answer. Valid SIPp and sipr scenario syntax; the probe's
/// URIs are literal because a SIPp UAS renders `[remote_ip]` empty (it is
/// the `-rsa`/target global, unset in server mode).
fn ooc_probing_uas_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="uas-ooc-probe">
  <recv request="INVITE"/>
  <send><![CDATA[
    SIP/2.0 180 Ringing
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]ProbeTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[local_ip]:[local_port];transport=[transport]>
    Content-Length: 0

  ]]></send>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]ProbeTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[local_ip]:[local_port];transport=[transport]>
    Content-Length: 0

  ]]></send>
  <recv request="ACK"/>
  <send><![CDATA[
    OPTIONS sip:probe@127.0.0.1 SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: probe <sip:probe@[local_ip]:[local_port]>;tag=[pid]probe[call_number]
    To: <sip:probe@127.0.0.1>
    Call-ID: ooc-probe-[call_number]-[pid]@[local_ip]
    CSeq: 7 OPTIONS
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv request="BYE"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[local_ip]:[local_port];transport=[transport]>
    Content-Length: 0

  ]]></send>
  <timewait milliseconds="500"/>
</scenario>
"#
}

/// Real sipp UAC with `-oocsn ooc_default` answers the out-of-call OPTIONS
/// sipr's UAS fires at it: sipp's error log carries SIPp's warning and the
/// 200s reach sipr as unmapped responses (its `unexpected` counter).
#[test]
fn real_sipp_ooc_scenario_answers_siprs_out_of_call_options() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::real_sipp_ooc_scenario_answers_siprs_out_of_call_options — no sipp."
        );
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let uas_path = dir.path().join("uas-ooc-probe.xml");
    std::fs::write(&uas_path, ooc_probing_uas_xml()).expect("write uas");
    let port = free_port();
    let mut sipr_uas = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .current_dir(dir.path())
            .args([
                "-sf",
                uas_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "3",
                "-timeout",
                "30",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipp_uac = Reaper(
        Command::new(&sipp)
            .current_dir(dir.path())
            .args([
                "-sn",
                "uac",
                "-oocsn",
                "ooc_default",
                "-i",
                "127.0.0.1",
                "-r",
                "10",
                "-m",
                "3",
                "-d",
                "300",
                "-timeout",
                "20s",
                "-trace_err",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
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
    assert!(stderr.contains("successful 3 failed 0"), "{stderr}");
    // sipp's ooc scenario answered each probe: the 200s are responses to no
    // sipr call, so sipr counted them as out-of-call (unexpected) messages.
    // On exit sipp also aborts its lingering ooc calls with a BYE each,
    // which sipr may or may not still be around to count.
    let unexpected = stderr
        .split(" unexpected ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0);
    assert!(unexpected >= 3, "expected >= 3 unmapped 200s:\n{stderr}");
    let sipp_errors = sipp_error_log(dir.path());
    assert_eq!(
        sipp_errors
            .matches("Received out-of-call OPTIONS message, using the out-of-call scenario")
            .count(),
        3,
        "sipp error log:\n{sipp_errors}"
    );
}

/// The concatenated sipp `*_errors.log` files in `dir`.
fn sipp_error_log(dir: &std::path::Path) -> String {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with("_errors.log"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .collect()
}

/// The mirror: sipr UAC with `-oocsn ooc_default` answers the out-of-call
/// OPTIONS real sipp's UAS fires at it, logging SIPp's warning. A SIPp UAS
/// spawns a main-scenario call for *any* message of no known call,
/// responses included, which then aborts on the 200 ("Aborting call on
/// unexpected message") and eats its `-m` budget — so sipp runs without
/// `-m`, is reaped once sipr is done, and that abort line is the proof
/// each 200 arrived.
#[test]
fn sipr_ooc_scenario_answers_real_sipps_out_of_call_options() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::sipr_ooc_scenario_answers_real_sipps_out_of_call_options — no sipp."
        );
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let uas_path = dir.path().join("uas-ooc-probe.xml");
    std::fs::write(&uas_path, ooc_probing_uas_xml()).expect("write uas");
    let port = free_port();
    let sipp_uas = Reaper(
        Command::new(&sipp)
            .current_dir(dir.path())
            .args([
                "-sf",
                uas_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-timeout",
                "30s",
                "-trace_err",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_uac = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .current_dir(dir.path())
            .args([
                "-sn",
                "uac",
                "-oocsn",
                "ooc_default",
                "-i",
                "127.0.0.1",
                "-r",
                "10",
                "-m",
                "3",
                "-d",
                "300",
                "-timeout",
                "20",
                "-trace_err",
                "-bg",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipr uac"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_uac.0, Duration::from_secs(25));
    let stderr = sipr_uac
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
        "sipr uac must exit 0; stderr:\n{stderr}"
    );
    assert!(stderr.contains("successful 3 failed 0"), "{stderr}");
    // The probes were answered by the ooc scenario, not counted against the
    // main one.
    assert!(stderr.contains(" unexpected 0 "), "{stderr}");
    let sipr_errors: String = std::fs::read_dir(dir.path())
        .expect("readdir")
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with("uac_") && n.ends_with("_errors.log")
        })
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .collect();
    assert!(
        sipr_errors
            .contains("Received out-of-call OPTIONS message, using the out-of-call scenario"),
        "sipr errors log:\n{sipr_errors}"
    );
    assert_eq!(
        sipr_errors.matches("Received out-of-call OPTIONS").count(),
        3,
        "one ooc call per probe:\n{sipr_errors}"
    );
    // Each probe's 200 reached sipp, where it aborted a bogus server-mode
    // call — one abort line per probe in sipp's error log.
    drop(sipp_uas);
    let sipp_errors = sipp_error_log(dir.path());
    let sipp_errors: String = sipp_errors
        .lines()
        .filter(|l| !l.contains("SIPrTag"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        sipp_errors
            .matches("Aborting call on unexpected message for Call-Id 'ooc-probe-")
            .count(),
        3,
        "sipp error log:\n{sipp_errors}"
    );
}

/// A UAC flow that lingers in timewait after its BYE: in mixed mode each
/// side's run ends with its *main* calls, so the timewait is what keeps a
/// side alive for the peer's last originated call.
fn mixed_uac_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="uac-timewait">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Subject: Mixed-mode test
    Content-Length: 0

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200" rtd="true"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <pause/>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200" crlf="true"/>
  <timewait milliseconds="3000"/>
</scenario>
"#
}

/// SIPp's classic UAS responder, as a file for `-rxsf` (SIPp 3.7 rejects
/// `-rxsn`: the option table spells it `rxrn` and the parser `rxsn`).
fn mixed_uas_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="uas-receive">
  <recv request="INVITE" crlf="true"/>
  <send><![CDATA[
    SIP/2.0 180 Ringing
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]SIPpTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[local_ip]:[local_port];transport=[transport]>
    Content-Length: 0

  ]]></send>
  <send retrans="500"><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]SIPpTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[local_ip]:[local_port];transport=[transport]>
    Content-Length: 0

  ]]></send>
  <recv request="ACK" rtd="true" crlf="true"/>
  <recv request="BYE"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[local_ip]:[local_port];transport=[transport]>
    Content-Length: 0

  ]]></send>
  <timewait milliseconds="4000"/>
</scenario>
"#
}

/// Read a reaped child's stderr to a string.
fn child_stderr(child: &mut Child) -> String {
    child
        .stderr
        .take()
        .map(|mut s| {
            use std::io::Read;
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            buf
        })
        .unwrap_or_default()
}

/// Mixed mode both ways: real sipp (`-sf uac -rxsf uas`) and sipr
/// (`-sf uac -rxsn uas`) each originate three calls to the other and
/// terminate the other's three on their receive scenario. sipp starts
/// first at one call per second (its first call comes one interval in),
/// sipr follows at three per second; each side's timewait keeps it alive
/// for the peer's last originated call (`socket.cpp` `MODE_MIXED`).
#[test]
fn real_sipp_and_sipr_terminate_each_others_calls_in_mixed_mode() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::real_sipp_and_sipr_terminate_each_others_calls_in_mixed_mode — no sipp."
        );
        return;
    };
    let sipp_dir = tempfile::tempdir().expect("tempdir");
    let sipr_dir = tempfile::tempdir().expect("tempdir");
    let uac_path = sipp_dir.path().join("uac-timewait.xml");
    let uas_path = sipp_dir.path().join("uas-receive.xml");
    std::fs::write(&uac_path, mixed_uac_xml()).expect("write uac");
    std::fs::write(&uas_path, mixed_uas_xml()).expect("write uas");
    let sipp_port = free_port();
    let sipr_port = free_port();
    let mut sipp_mixed = Reaper(
        Command::new(&sipp)
            .current_dir(sipp_dir.path())
            .args([
                "-sf",
                uac_path.to_str().expect("utf8"),
                "-rxsf",
                uas_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &sipp_port.to_string(),
                "-r",
                "1",
                "-m",
                "3",
                "-d",
                "300",
                "-timeout",
                "30s",
                "-trace_err",
                &format!("127.0.0.1:{sipr_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp mixed"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_mixed = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .current_dir(sipr_dir.path())
            .args([
                "-sf",
                uac_path.to_str().expect("utf8"),
                "-rxsn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &sipr_port.to_string(),
                "-r",
                "3",
                "-m",
                "3",
                "-d",
                "300",
                "-timeout",
                "30",
                "-trace_err",
                "-bg",
                &format!("127.0.0.1:{sipp_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipr mixed"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_mixed.0, Duration::from_secs(25));
    let stderr = child_stderr(&mut sipr_mixed.0);
    assert_eq!(sipr_code, Some(0), "sipr must exit 0; stderr:\n{stderr}");
    // sipr's own three calls were answered by sipp's receive scenario…
    assert!(stderr.contains("successful 3 failed 0"), "{stderr}");
    assert!(stderr.contains(" unexpected 0 "), "{stderr}");
    // …and sipp's three were answered by sipr's: sipp exits 0 only when all
    // of its main calls succeeded.
    let sipp_code = wait_with_timeout(&mut sipp_mixed.0, Duration::from_secs(25));
    let sipp_errors = sipp_error_log(sipp_dir.path());
    assert_eq!(
        sipp_code,
        Some(0),
        "sipp must exit 0; its error log:\n{sipp_errors}"
    );
    let sipr_errors = sipp_error_log(sipr_dir.path());
    assert_eq!(
        sipr_errors
            .matches("Received INVITE for no known call, using the receive scenario")
            .count(),
        3,
        "sipr error log:\n{sipr_errors}"
    );
}

/// sipr in mixed mode between two plain sipps: its main scenario calls a
/// real sipp UAS while its receive scenario terminates the calls a real
/// sipp UAC places at it.
#[test]
fn sipr_receive_scenario_answers_a_plain_real_sipp_uac() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::sipr_receive_scenario_answers_a_plain_real_sipp_uac — no sipp."
        );
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let uac_path = dir.path().join("uac-timewait.xml");
    std::fs::write(&uac_path, mixed_uac_xml()).expect("write uac");
    let uas_port = free_port();
    let sipr_port = free_port();
    let _sipp_uas = Reaper(
        Command::new(&sipp)
            .current_dir(dir.path())
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &uas_port.to_string(),
                "-timeout",
                "30s",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_mixed = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .current_dir(dir.path())
            .args([
                "-sf",
                uac_path.to_str().expect("utf8"),
                "-rxsn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &sipr_port.to_string(),
                "-r",
                "3",
                "-m",
                "3",
                "-d",
                "300",
                "-timeout",
                "30",
                "-bg",
                &format!("127.0.0.1:{uas_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipr mixed"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipp_uac = Reaper(
        Command::new(&sipp)
            .current_dir(dir.path())
            .args([
                "-sn",
                "uac",
                "-i",
                "127.0.0.1",
                "-r",
                "3",
                "-m",
                "3",
                "-d",
                "300",
                "-timeout",
                "20s",
                "-trace_err",
                &format!("127.0.0.1:{sipr_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp uac"),
    );
    let sipp_code = wait_with_timeout(&mut sipp_uac.0, Duration::from_secs(20));
    let sipp_errors = sipp_error_log(dir.path());
    assert_eq!(
        sipp_code,
        Some(0),
        "sipp uac must exit 0 (sipr's receive scenario answered it); error log:\n{sipp_errors}"
    );
    let sipr_code = wait_with_timeout(&mut sipr_mixed.0, Duration::from_secs(20));
    let stderr = child_stderr(&mut sipr_mixed.0);
    assert_eq!(sipr_code, Some(0), "sipr must exit 0; stderr:\n{stderr}");
    assert!(stderr.contains("successful 3 failed 0"), "{stderr}");
    assert!(stderr.contains(" unexpected 0 "), "{stderr}");
}

// ---- <User>/<Global> variables against real sipp (M35) -------------------

/// The counter scenario as a UAC: a `<User>` counter, a `<Global>` counter,
/// both reported with `[userid]` in INVITE headers. The same file drives
/// real sipp and sipr.
fn counter_uac_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">
<scenario name="counters">
  <Global variables="per_run"/>
  <User variables="per_user"/>
  <nop>
    <action>
      <add assign_to="per_user" value="1"/>
      <add assign_to="per_run" value="1"/>
    </action>
  </nop>
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:u[userid]@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:u[userid]@[local_ip]:[local_port]
    X-User: [userid]
    X-User-Count: [$per_user]
    X-Run-Count: [$per_run]
    Max-Forwards: 70
    Subject: Performance Test
    Content-Type: application/sdp
    Content-Length: [len]

    v=0
    o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
    s=-
    c=IN IP[media_ip_type] [media_ip]
    t=0 0
    m=audio [media_port] RTP/AVP 0
    a=rtpmap:0 PCMU/8000

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200" rtd="true"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:u[userid]@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Contact: sip:u[userid]@[local_ip]:[local_port]
    Max-Forwards: 70
    Subject: Performance Test
    Content-Length: 0

  ]]></send>
  <pause/>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:u[userid]@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Contact: sip:u[userid]@[local_ip]:[local_port]
    Max-Forwards: 70
    Subject: Performance Test
    Content-Length: 0

  ]]></send>
  <recv response="200" crlf="true"/>
</scenario>
"#
}

/// `(X-User, X-User-Count, X-Run-Count)` of every INVITE in a `-trace_msg`
/// log (sipp's or sipr's), in order, retransmissions folded.
fn counter_headers_in_message_log(dir: &std::path::Path) -> Vec<(String, String, String)> {
    let log: String = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with("_messages.log"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .collect();
    let mut calls: Vec<(String, String, String)> = Vec::new();
    for block in log.split("INVITE sip:").skip(1) {
        let header = |name: &str| {
            block
                .lines()
                .take_while(|l| !l.trim().is_empty())
                .find_map(|l| l.strip_prefix(name))
                .map(|v| v.trim_start_matches(':').trim().to_owned())
                .unwrap_or_default()
        };
        let call = (
            header("X-User"),
            header("X-User-Count"),
            header("X-Run-Count"),
        );
        if !calls.contains(&call) {
            calls.push(call);
        }
    }
    calls
}

/// The counter scenario run by real sipp (`-users 2 -m 6`) against a sipr
/// UAS, and by sipr against a sipp UAS: both sides hand out user ids the
/// same way (user 2 first, then alternating) and keep the per-user counter
/// per user id (1, 2, 3 for each) and the global one across the run (each
/// of 1..6 once). Two things are normalised before comparing, both
/// pre-existing and recorded in SIPP_COMPAT §6: sipp renders a double as
/// `%lf` ("2.000000", sipr "2"), and sipp's scheduler runs one step per
/// call per turn, so when two calls start in the same tick both `<nop>`s
/// run before either INVITE renders and the first two INVITEs both carry
/// global 2 (sipr runs a call to its first blocking step, so they carry
/// 1 and 2).
#[test]
fn user_and_global_variables_count_the_same_as_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::user_and_global_variables_count_the_same_as_real_sipp — no sipp."
        );
        return;
    };
    let read_stderr = |child: &mut Child| {
        child
            .stderr
            .take()
            .map(|mut s| {
                use std::io::Read;
                let mut buf = String::new();
                let _ = s.read_to_string(&mut buf);
                buf
            })
            .unwrap_or_default()
    };

    // sipp UAC → sipr UAS.
    let dir_a = tempfile::tempdir().expect("tempdir");
    let xml_a = dir_a.path().join("counters.xml");
    std::fs::write(&xml_a, counter_uac_xml()).expect("write scenario");
    let port = free_port();
    let mut sipr_uas = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .current_dir(dir_a.path())
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "6",
                "-timeout",
                "30",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipp_uac = Reaper(
        Command::new(&sipp)
            .current_dir(dir_a.path())
            .args([
                "-sf",
                xml_a.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-users",
                "2",
                "-m",
                "6",
                "-d",
                "200",
                "-timeout",
                "20s",
                "-trace_msg",
                "-trace_err",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp uac"),
    );
    let sipp_code = wait_with_timeout(&mut sipp_uac.0, Duration::from_secs(25));
    assert_eq!(
        sipp_code,
        Some(0),
        "sipp uac must exit 0; sipp errors:\n{}",
        sipp_error_log(dir_a.path())
    );
    let sipr_code = wait_with_timeout(&mut sipr_uas.0, Duration::from_secs(15));
    let stderr = read_stderr(&mut sipr_uas.0);
    assert_eq!(
        sipr_code,
        Some(0),
        "sipr uas must exit 0; stderr:\n{stderr}"
    );
    assert!(stderr.contains("successful 6 failed 0"), "{stderr}");
    let by_sipp = counter_headers_in_message_log(dir_a.path());

    // sipr UAC → sipp UAS.
    let dir_b = tempfile::tempdir().expect("tempdir");
    let xml_b = dir_b.path().join("counters.xml");
    std::fs::write(&xml_b, counter_uac_xml()).expect("write scenario");
    let port = free_port();
    let mut sipp_uas = Reaper(
        Command::new(&sipp)
            .current_dir(dir_b.path())
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "6",
                "-timeout",
                "30",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_uac = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .current_dir(dir_b.path())
            .args([
                "-sf",
                xml_b.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-users",
                "2",
                "-m",
                "6",
                "-d",
                "200",
                "-timeout",
                "20",
                "-trace_msg",
                "-bg",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipr uac"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_uac.0, Duration::from_secs(25));
    let stderr = read_stderr(&mut sipr_uac.0);
    assert_eq!(
        sipr_code,
        Some(0),
        "sipr uac must exit 0; stderr:\n{stderr}"
    );
    assert!(stderr.contains("successful 6 failed 0"), "{stderr}");
    let _ = wait_with_timeout(&mut sipp_uas.0, Duration::from_secs(15));
    let by_sipr = counter_headers_in_message_log(dir_b.path());

    for (who, calls) in [("real sipp", &by_sipp), ("sipr", &by_sipr)] {
        let num = |s: &str| s.parse::<f64>().unwrap_or(-1.0);
        let users: Vec<&str> = calls.iter().map(|(u, _, _)| u.as_str()).collect();
        assert_eq!(
            users,
            ["2", "1", "2", "1", "2", "1"],
            "{who}: user order {calls:?}"
        );
        for user in ["1", "2"] {
            let counts: Vec<f64> = calls
                .iter()
                .filter(|(u, _, _)| u == user)
                .map(|(_, c, _)| num(c))
                .collect();
            assert_eq!(
                counts,
                [1.0, 2.0, 3.0],
                "{who}: user {user}'s counter {calls:?}"
            );
        }
        // The global counter never goes back and has counted every call
        // by the last one; sipr reads 1..6 exactly (sipp 2, 2, 3, 4, 5, 6 —
        // see above).
        let globals: Vec<f64> = calls.iter().map(|(_, _, r)| num(r)).collect();
        assert!(
            globals.windows(2).all(|w| w[0] <= w[1]),
            "{who}: global counter {calls:?}"
        );
        assert_eq!(
            globals.last(),
            Some(&6.0),
            "{who}: global counter {calls:?}"
        );
    }
    let sipr_globals: Vec<f64> = by_sipr
        .iter()
        .map(|(_, _, r)| r.parse::<f64>().unwrap_or(-1.0))
        .collect();
    assert_eq!(sipr_globals, [1.0, 2.0, 3.0, 4.0, 5.0, 6.0], "{by_sipr:?}");
}

// ---- manual transactions against real sipp (M36) -------------------------

/// SIPp's basic UAC flow with every transaction named: the INVITE and its
/// ACK by `invite`, the BYE by `bye`. Runs unchanged on sipp and sipr.
fn txn_uac_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">
<scenario name="txn-uac">
  <send retrans="500" start_txn="invite"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Subject: Performance Test
    Content-Type: application/sdp
    Content-Length: [len]

    v=0
    o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
    s=-
    c=IN IP[media_ip_type] [media_ip]
    t=0 0
    m=audio [media_port] RTP/AVP 0
    a=rtpmap:0 PCMU/8000

  ]]></send>
  <recv response="100" optional="true" response_txn="invite"/>
  <recv response="180" optional="true" response_txn="invite"/>
  <recv response="200" rtd="true" response_txn="invite"/>
  <send ack_txn="invite"><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Subject: Performance Test
    Content-Length: 0

  ]]></send>
  <pause/>
  <send retrans="500" start_txn="bye"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Subject: Performance Test
    Content-Length: 0

  ]]></send>
  <recv response="200" crlf="true" response_txn="bye"/>
</scenario>
"#
}

/// The named-transaction UAC flow run by real sipp against a sipr UAS and
/// by sipr against a sipp UAS: every response is taken by the transaction
/// it belongs to and both sides finish every call cleanly.
#[test]
fn manual_transactions_complete_against_real_sipp_both_ways() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::manual_transactions_complete_against_real_sipp_both_ways — no sipp."
        );
        return;
    };
    let read_stderr = |child: &mut Child| {
        child
            .stderr
            .take()
            .map(|mut s| {
                use std::io::Read;
                let mut buf = String::new();
                let _ = s.read_to_string(&mut buf);
                buf
            })
            .unwrap_or_default()
    };

    // sipp UAC → sipr UAS.
    let dir_a = tempfile::tempdir().expect("tempdir");
    let xml_a = dir_a.path().join("txn-uac.xml");
    std::fs::write(&xml_a, txn_uac_xml()).expect("write scenario");
    let port = free_port();
    let mut sipr_uas = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .current_dir(dir_a.path())
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "4",
                "-timeout",
                "30",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipp_uac = Reaper(
        Command::new(&sipp)
            .current_dir(dir_a.path())
            .args([
                "-sf",
                xml_a.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-r",
                "10",
                "-m",
                "4",
                "-d",
                "200",
                "-timeout",
                "20s",
                "-trace_err",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp uac"),
    );
    let sipp_code = wait_with_timeout(&mut sipp_uac.0, Duration::from_secs(25));
    assert_eq!(
        sipp_code,
        Some(0),
        "sipp uac must exit 0; sipp errors:\n{}",
        sipp_error_log(dir_a.path())
    );
    let sipr_code = wait_with_timeout(&mut sipr_uas.0, Duration::from_secs(15));
    let stderr = read_stderr(&mut sipr_uas.0);
    assert_eq!(
        sipr_code,
        Some(0),
        "sipr uas must exit 0; stderr:\n{stderr}"
    );
    assert!(stderr.contains("successful 4 failed 0"), "{stderr}");

    // sipr UAC → sipp UAS.
    let dir_b = tempfile::tempdir().expect("tempdir");
    let xml_b = dir_b.path().join("txn-uac.xml");
    std::fs::write(&xml_b, txn_uac_xml()).expect("write scenario");
    let port = free_port();
    let mut sipp_uas = Reaper(
        Command::new(&sipp)
            .current_dir(dir_b.path())
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "4",
                "-timeout",
                "30",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_uac = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sipr"))
            .current_dir(dir_b.path())
            .args([
                "-sf",
                xml_b.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-r",
                "10",
                "-m",
                "4",
                "-d",
                "200",
                "-timeout",
                "20",
                "-bg",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sipr uac"),
    );
    let sipr_code = wait_with_timeout(&mut sipr_uac.0, Duration::from_secs(25));
    let stderr = read_stderr(&mut sipr_uac.0);
    assert_eq!(
        sipr_code,
        Some(0),
        "sipr uac must exit 0; stderr:\n{stderr}"
    );
    assert!(stderr.contains("successful 4 failed 0"), "{stderr}");
    assert!(!stderr.contains("unexpected 1"), "{stderr}");
    let _ = wait_with_timeout(&mut sipp_uas.0, Duration::from_secs(15));
}

// ---- exec command= and setdest against real sipp (M37) --------------------

const SIPP_XML_HEADER: &str =
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n";

/// A UAS that runs `echo [last_From:] >> from_list.log` per INVITE.
fn exec_uas_xml() -> String {
    format!(
        r#"{SIPP_XML_HEADER}<scenario name="exec-uas">
  <recv request="INVITE">
    <action>
      <exec command="echo '[last_From:]' >> from_list.log"/>
    </action>
  </recv>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]SIPpTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[local_ip]:[local_port];transport=[transport]>
    Content-Length: 0

  ]]></send>
  <recv request="ACK"/>
  <recv request="BYE"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:]
    [last_Call-ID:]
    [last_CSeq:]
    Content-Length: 0

  ]]></send>
</scenario>
"#
    )
}

/// The UAC of SIPp's setdest example: after the ACK, `ereg` the host and
/// port out of `[next_url]` and `setdest` there; the BYE goes to that peer.
fn setdest_uac_xml() -> String {
    format!(
        r#"{SIPP_XML_HEADER}<scenario name="setdest-uac">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Subject: Performance Test
    Content-Length: 0

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200" rtd="true" rrs="true"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Subject: Performance Test
    Content-Length: 0

  ]]></send>
  <nop>
    <action>
      <assignstr assign_to="url" value="[next_url]"/>
      <ereg regexp="sip:.*@([0-9A-Za-z\.]+):([0-9]+)" search_in="var" variable="url"
            check_it="true" assign_to="dummy,host,port"/>
      <setdest host="[$host]" port="[$port]" protocol="udp"/>
    </action>
  </nop>
  <pause milliseconds="100"/>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Contact: sip:sipp@[local_ip]:[local_port]
    Max-Forwards: 70
    Subject: Performance Test
    Content-Length: 0

  ]]></send>
  <recv response="200" crlf="true"/>
  <Reference variables="dummy"/>
</scenario>
"#
    )
}

/// The first peer: answers the INVITE with a Contact on `redirect_port`,
/// takes the ACK, and that is the whole call for it.
fn redirecting_uas_xml(redirect_port: u16) -> String {
    format!(
        r#"{SIPP_XML_HEADER}<scenario name="redirecting-uas">
  <recv request="INVITE"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]SIPpTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[service]@127.0.0.1:{redirect_port}>
    Content-Length: 0

  ]]></send>
  <recv request="ACK"/>
</scenario>
"#
    )
}

/// The second peer: only ever sees the BYE.
fn bye_uas_xml() -> String {
    format!(
        r#"{SIPP_XML_HEADER}<scenario name="bye-uas">
  <recv request="BYE"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:]
    [last_Call-ID:]
    [last_CSeq:]
    Content-Length: 0

  ]]></send>
</scenario>
"#
    )
}

/// Spawn a UAS (sipp or sipr) on `port` with `-m calls` in `dir`.
fn spawn_uas_bin(
    bin: &std::path::Path,
    xml: &std::path::Path,
    port: u16,
    calls: u32,
    dir: &std::path::Path,
) -> Reaper {
    Reaper(
        Command::new(bin)
            .current_dir(dir)
            .args([
                "-sf",
                xml.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                &calls.to_string(),
                "-timeout",
                "30",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uas"),
    )
}

/// `exec command=` on both sides: real sipp's UAC into a sipr UAS running
/// the echo hook, and sipr's UAC into a sipp UAS running it. Each side's
/// `from_list.log` gets one line per call (the hook ran once per INVITE,
/// through a shell, in the UAS's directory); sipr's lines carry the From
/// header, sipp's are empty — see below.
#[test]
fn exec_command_writes_the_same_hook_output_as_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::exec_command_writes_the_same_hook_output_as_real_sipp — no sipp."
        );
        return;
    };
    let sipr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let mut logs = Vec::new();
    for (uas_bin, uac_bin, uac_extra) in [
        (&sipr, &sipp, vec!["-timeout", "20s"]),
        (&sipp, &sipr, vec!["-timeout", "20", "-bg"]),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let xml = dir.path().join("exec-uas.xml");
        std::fs::write(&xml, exec_uas_xml()).expect("write uas");
        let port = free_port();
        let mut uas = spawn_uas_bin(uas_bin, &xml, port, 3, dir.path());
        std::thread::sleep(Duration::from_millis(400));
        let mut args = vec![
            "-sn".to_owned(),
            "uac".to_owned(),
            "-i".to_owned(),
            "127.0.0.1".to_owned(),
            "-r".to_owned(),
            "10".to_owned(),
            "-m".to_owned(),
            "3".to_owned(),
            "-d".to_owned(),
            "100".to_owned(),
        ];
        args.extend(uac_extra.iter().map(|s| (*s).to_owned()));
        args.push(format!("127.0.0.1:{port}"));
        let mut uac = Reaper(
            Command::new(uac_bin)
                .current_dir(dir.path())
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn uac"),
        );
        assert_eq!(
            wait_with_timeout(&mut uac.0, Duration::from_secs(25)),
            Some(0),
            "uac exit"
        );
        let code = wait_with_timeout(&mut uas.0, Duration::from_secs(15));
        let stderr = child_stderr(&mut uas.0);
        assert_eq!(code, Some(0), "uas exit; stderr:\n{stderr}");
        let log = std::fs::read_to_string(dir.path().join("from_list.log")).unwrap_or_default();
        let listing: Vec<String> = std::fs::read_dir(dir.path())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            log.lines().count(),
            3,
            "uas {}: log {log:?}; dir {listing:?}; uas stderr:\n{stderr}\nsipp errors:\n{}",
            uas_bin.display(),
            sipp_error_log(dir.path())
        );
        // Real sipp writes three *empty* lines here: `[last_From:]` renders
        // nothing inside the recv's own actions, because SIPp stores the
        // received message for `[last_*]` only after running them
        // (SIPP_COMPAT §6). sipr has the header at that point.
        if uas_bin == &sipr {
            assert!(
                log.lines()
                    .all(|l| l.starts_with("From: ") && l.contains("@127.0.0.1:")),
                "uas {}: log {log:?}",
                uas_bin.display()
            );
        }
        logs.push(log);
    }
}

/// SIPp's own setdest idiom both ways: a UAC redirected by the 200's
/// Contact sends its BYE to a second peer. sipp UAC against sipr peers,
/// sipr UAC against sipp peers; every call completes on every side.
#[test]
fn setdest_redirects_to_a_second_peer_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::setdest_redirects_to_a_second_peer_like_real_sipp — no sipp.");
        return;
    };
    let sipr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    for (peer_bin, uac_bin, uac_extra) in [
        (&sipr, &sipp, vec!["-timeout", "20s"]),
        (&sipp, &sipr, vec!["-timeout", "20", "-bg"]),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let port1 = free_port();
        let port2 = free_port();
        let uas1_xml = dir.path().join("redirecting-uas.xml");
        let uas2_xml = dir.path().join("bye-uas.xml");
        let uac_xml = dir.path().join("setdest-uac.xml");
        std::fs::write(&uas1_xml, redirecting_uas_xml(port2)).expect("write uas1");
        std::fs::write(&uas2_xml, bye_uas_xml()).expect("write uas2");
        std::fs::write(&uac_xml, setdest_uac_xml()).expect("write uac");
        let mut uas1 = spawn_uas_bin(peer_bin, &uas1_xml, port1, 3, dir.path());
        let mut uas2 = spawn_uas_bin(peer_bin, &uas2_xml, port2, 3, dir.path());
        std::thread::sleep(Duration::from_millis(500));
        let mut args = vec![
            "-sf".to_owned(),
            uac_xml.to_str().expect("utf8").to_owned(),
            "-i".to_owned(),
            "127.0.0.1".to_owned(),
            "-r".to_owned(),
            "10".to_owned(),
            "-m".to_owned(),
            "3".to_owned(),
            "-trace_err".to_owned(),
        ];
        args.extend(uac_extra.iter().map(|s| (*s).to_owned()));
        args.push(format!("127.0.0.1:{port1}"));
        let mut uac = Reaper(
            Command::new(uac_bin)
                .current_dir(dir.path())
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn uac"),
        );
        let uac_code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
        let uac_err = child_stderr(&mut uac.0);
        assert_eq!(
            uac_code,
            Some(0),
            "uac exit; stderr:\n{uac_err}\nsipp errors:\n{}",
            sipp_error_log(dir.path())
        );
        for (name, uas) in [("redirecting", &mut uas1), ("bye", &mut uas2)] {
            let code = wait_with_timeout(&mut uas.0, Duration::from_secs(15));
            let stderr = child_stderr(&mut uas.0);
            assert_eq!(code, Some(0), "{name} peer exit; stderr:\n{stderr}");
        }
    }
}

// ---- M38: statistical pauses and <sample> -----------------------------

/// A UAC sending one OPTIONS per call, then every statistical pause SIPp
/// names (SIPp's own attribute spellings) plus two `<sample>` draws read
/// back by `<pause variable=>`. Parameters are in milliseconds and small,
/// so a call lasts well under a second.
const STATISTICAL_PAUSES_UAC: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="statistical pauses">
  <send retrans="500"><![CDATA[
OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
To: <sip:[service]@[remote_ip]:[remote_port]>
Call-ID: [call_id]
CSeq: 1 OPTIONS
Contact: <sip:sipp@[local_ip]:[local_port]>
Max-Forwards: 70
Content-Length: 0

]]></send>
  <recv response="200">
    <action>
      <sample assign_to="jitter" distribution="normal" mean="20" stdev="5"/>
      <sample assign_to="think" distribution="uniform" min="5" max="15"/>
    </action>
  </recv>
  <pause distribution="fixed" value="10"/>
  <pause distribution="uniform" min="5" max="15"/>
  <pause distribution="normal" mean="10" stdev="2"/>
  <pause distribution="lognormal" mean="2" stdev="0.5"/>
  <pause distribution="exponential" mean="10"/>
  <pause distribution="weibull" lambda="10" k="4"/>
  <pause distribution="pareto" k="3" x_m="5"/>
  <pause distribution="gpareto" shape="0.5" scale="5" location="1"/>
  <pause distribution="gamma" k="3" theta="2"/>
  <pause distribution="negbin" p="0.5" n="4"/>
  <pause min="5" max="10"/>
  <pause variable="think"/>
  <pause variable="jitter"/>
</scenario>
"#;

/// The matching UAS: answer each OPTIONS with a 200 mirroring the request.
const STATISTICAL_PAUSES_UAS: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="options responder">
  <recv request="OPTIONS" crlf="true"/>
  <send><![CDATA[
SIP/2.0 200 OK
[last_Via:]
[last_From:]
[last_To:];tag=[pid]SIPpTag01[call_number]
[last_Call-ID:]
[last_CSeq:]
Contact: <sip:[local_ip]:[local_port];transport=[transport]>
Content-Length: 0

]]></send>
</scenario>
"#;

/// Run the statistical-pauses UAC on `uac_bin` against the responder on
/// `uas_bin`, `calls` calls; return (uac exit, uas exit, uac stderr).
fn run_statistical_pauses_pair(
    uas_bin: &std::path::Path,
    uac_bin: &std::path::Path,
    calls: u32,
    tag: &str,
) -> (Option<i32>, Option<i32>, String) {
    run_sf_pair(
        uas_bin,
        uac_bin,
        STATISTICAL_PAUSES_UAS,
        STATISTICAL_PAUSES_UAC,
        &[],
        calls,
        tag,
    )
}

/// Run `uac_xml` on `uac_bin` (with `uac_extra` flags) against `uas_xml`
/// on `uas_bin`, `calls` calls; return (uac exit, uas exit, uac stderr).
/// Either binary may be sipr or real sipp.
fn run_sf_pair(
    uas_bin: &std::path::Path,
    uac_bin: &std::path::Path,
    uas_xml: &str,
    uac_xml: &str,
    uac_extra: &[&str],
    calls: u32,
    tag: &str,
) -> (Option<i32>, Option<i32>, String) {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let uas_path = dir.join(format!("sipr-interop-pair-uas-{tag}-{pid}.xml"));
    let uac_path = dir.join(format!("sipr-interop-pair-uac-{tag}-{pid}.xml"));
    std::fs::write(&uas_path, uas_xml).expect("write uas");
    std::fs::write(&uac_path, uac_xml).expect("write uac");
    let port = free_port();
    let mut uas = Reaper(
        Command::new(uas_bin)
            .current_dir(&dir)
            .args([
                "-sf",
                uas_path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                &calls.to_string(),
                "-timeout",
                "30",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    // `-bg` is sipr's headless switch (periodic stat lines on stderr);
    // sipp's `-bg` forks and the parent exits 99 at once (docs/TESTING.md),
    // so real sipp runs in the foreground with its screen on a null stdout.
    let mut args = vec![
        "-sf".to_owned(),
        uac_path.to_str().expect("utf8").to_owned(),
        "-i".to_owned(),
        "127.0.0.1".to_owned(),
        "-r".to_owned(),
        "10".to_owned(),
        "-m".to_owned(),
        calls.to_string(),
        "-timeout".to_owned(),
        "20".to_owned(),
    ];
    let uac_is_sipr = uac_bin == std::path::Path::new(env!("CARGO_BIN_EXE_sipr"));
    if uac_is_sipr {
        args.push("-bg".to_owned());
    }
    args.extend(uac_extra.iter().map(|a| (*a).to_owned()));
    args.push(format!("127.0.0.1:{port}"));
    let mut uac = Reaper(
        Command::new(uac_bin)
            .current_dir(&dir)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uac"),
    );
    let uac_code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    let stderr = uac
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
    let uas_code = wait_with_timeout(&mut uas.0, Duration::from_secs(15));
    let _ = std::fs::remove_file(&uas_path);
    let _ = std::fs::remove_file(&uac_path);
    (uac_code, uas_code, stderr)
}

/// Every statistical pause and `<sample>`, both ways: sipr's UAC runs the
/// scenario against real sipp's UAS, and real sipp's UAC runs the same file
/// against sipr's UAS. A sipp built without GSL refuses the scenario ("is
/// only available with GSL"); that is an environment limit of sipp's, not a
/// behavior to compare against — skipped visibly.
#[test]
fn statistical_pauses_both_ways_against_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::statistical_pauses_both_ways_against_real_sipp — no sipp.");
        return;
    };
    let sipr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let (uac_code, uas_code, stderr) = run_statistical_pauses_pair(&sipp, &sipr, 3, "sipr-uac");
    assert_eq!(uac_code, Some(0), "sipr uac stderr:\n{stderr}");
    assert!(stderr.contains("successful 3 failed 0"), "{stderr}");
    assert_eq!(uas_code, Some(0), "sipp uas exited {uas_code:?}");

    let dir = std::env::temp_dir();
    let (uac_code, uas_code, _) = run_statistical_pauses_pair(&sipr, &sipp, 3, "sipp-uac");
    if sipp_error_log_contains(&dir, "only available with GSL") {
        eprintln!(
            "SKIPPED interop::statistical_pauses_both_ways_against_real_sipp (sipp side) — \
             sipp built without GSL refuses statistical pauses."
        );
        return;
    }
    assert_eq!(uac_code, Some(0), "sipp uac exited {uac_code:?}");
    assert_eq!(uas_code, Some(0), "sipr uas exited {uas_code:?}");
}

// ---- M39: keyword parity -------------------------------------------------

/// A UAC using the M39 keywords SIPp also has: a `-key` generic keyword,
/// `[remote_host]`, `[dynamic_id]`, `[clock_tick]`, `[sipp_version]`,
/// `[date]`, `[timestamp]`, then `[last_cseq_number+1]` and `[fill]` sized
/// by a variable captured from the 200.
const M39_KEYWORDS_UAC: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="m39 keywords">
  <send retrans="500"><![CDATA[
OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
To: <sip:[service]@[remote_ip]:[remote_port]>
Call-ID: [call_id]
CSeq: 1 OPTIONS
Contact: <sip:sipp@[local_ip]:[local_port]>
Max-Forwards: 70
X-Pbx: [pbx]
X-Host: [remote_host]
X-Dyn: [dynamic_id]
X-Tick: [clock_tick]
X-Ver: [sipp_version]
Date: [date]
X-Stamp: [timestamp]
Content-Length: 0

]]></send>
  <recv response="200">
    <action>
      <ereg regexp="([0-9]+)" search_in="hdr" header="CSeq:" check_it="true" assign_to="whole,n"/>
      <todouble assign_to="len" variable="n"/>
    </action>
  </recv>
  <send retrans="500"><![CDATA[
OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
To: <sip:[service]@[remote_ip]:[remote_port]>
Call-ID: [call_id]
CSeq: [last_cseq_number+1] OPTIONS
Max-Forwards: 70
X-Fill: [fill variable=len text="ab"]
Content-Length: 0

]]></send>
  <recv response="200"/>
  <Reference variables="whole"/>
</scenario>
"#;

/// The M39 UAC sends two OPTIONS per call, so its responder answers two
/// (a SIPp UAS scenario ends after its last step; a second request to a
/// finished call is not answered).
const M39_KEYWORDS_UAS: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="options responder, two rounds">
  <recv request="OPTIONS" crlf="true"/>
  <send><![CDATA[
SIP/2.0 200 OK
[last_Via:]
[last_From:]
[last_To:];tag=[pid]SIPpTag01[call_number]
[last_Call-ID:]
[last_CSeq:]
Contact: <sip:[local_ip]:[local_port];transport=[transport]>
Content-Length: 0

]]></send>
  <recv request="OPTIONS" crlf="true"/>
  <send><![CDATA[
SIP/2.0 200 OK
[last_Via:]
[last_From:]
[last_To:];tag=[pid]SIPpTag01[call_number]
[last_Call-ID:]
[last_CSeq:]
Contact: <sip:[local_ip]:[local_port];transport=[transport]>
Content-Length: 0

]]></send>
</scenario>
"#;

/// The M39 keywords both ways: sipr's UAC against real sipp's OPTIONS
/// responder, and real sipp's UAC running the same file (same `-key`)
/// against sipr's responder; every call completes on both sides.
#[test]
fn m39_keywords_both_ways_against_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::m39_keywords_both_ways_against_real_sipp — no sipp.");
        return;
    };
    let sipr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let key = ["-key", "pbx", "pbx-1.example"];
    let (uac_code, uas_code, stderr) = run_sf_pair(
        &sipp,
        &sipr,
        M39_KEYWORDS_UAS,
        M39_KEYWORDS_UAC,
        &key,
        3,
        "m39-sipr-uac",
    );
    assert_eq!(uac_code, Some(0), "sipr uac stderr:\n{stderr}");
    assert!(stderr.contains("successful 3 failed 0"), "{stderr}");
    assert_eq!(uas_code, Some(0), "sipp uas exited {uas_code:?}");

    let (uac_code, uas_code, _) = run_sf_pair(
        &sipr,
        &sipp,
        M39_KEYWORDS_UAS,
        M39_KEYWORDS_UAC,
        &key,
        3,
        "m39-sipp-uac",
    );
    assert_eq!(uac_code, Some(0), "sipp uac exited {uac_code:?}");
    assert_eq!(uas_code, Some(0), "sipr uas exited {uas_code:?}");
}

// ---- M40: statistics files -------------------------------------------

/// Run the embedded UAC of `uac_bin` against the embedded UAS of `uas_bin`
/// with every statistics file on, in its own directory; return that
/// directory (the caller reads the files) and the UAC's exit code.
fn run_with_stat_files(
    uas_bin: &std::path::Path,
    uac_bin: &std::path::Path,
    tag: &str,
) -> (std::path::PathBuf, Option<i32>) {
    let dir = std::env::temp_dir().join(format!("sipr-interop-stats-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let port = free_port();
    let mut uas = Reaper(
        Command::new(uas_bin)
            .current_dir(&dir)
            .args([
                "-sn",
                "uas",
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "3",
                "-timeout",
                "30",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let uac_is_sipr = uac_bin == std::path::Path::new(env!("CARGO_BIN_EXE_sipr"));
    let mut args: Vec<String> = [
        "-sn",
        "uac",
        "-i",
        "127.0.0.1",
        "-r",
        "10",
        "-m",
        "3",
        "-d",
        "50",
        "-timeout",
        "20",
        "-fd",
        "1",
        "-trace_stat",
        "-trace_rtt",
        "-rtt_freq",
        "1",
        "-trace_counts",
        "-trace_error_codes",
    ]
    .iter()
    .map(|a| (*a).to_owned())
    .collect();
    if uac_is_sipr {
        args.push("-bg".to_owned());
    }
    args.push(format!("127.0.0.1:{port}"));
    let mut uac = Reaper(
        Command::new(uac_bin)
            .current_dir(&dir)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn uac"),
    );
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    let _ = wait_with_timeout(&mut uas.0, Duration::from_secs(15));
    (dir, code)
}

/// The header line of the file in `dir` whose name ends with `suffix`.
fn stat_file_header(dir: &std::path::Path, suffix: &str) -> String {
    let name = std::fs::read_dir(dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.ends_with(suffix))
        .unwrap_or_else(|| panic!("no *{suffix} in {}", dir.display()));
    let text = std::fs::read_to_string(dir.join(&name)).expect("read");
    text.lines().next().unwrap_or_default().to_owned()
}

/// The statistics files at parity: sipr and real sipp run the same embedded
/// UAC (same RTDs, same repartitions) and their `-trace_stat`,
/// `-trace_rtt` and `-trace_counts` headers are byte-for-byte equal; the
/// rows have the headers' column counts on both sides.
#[test]
fn statistics_file_headers_match_real_sipps() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::statistics_file_headers_match_real_sipps — no sipp.");
        return;
    };
    let sipr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let (sipr_dir, sipr_code) = run_with_stat_files(&sipp, &sipr, "sipr");
    assert_eq!(sipr_code, Some(0), "sipr uac");
    let (sipp_dir, _) = run_with_stat_files(&sipr, &sipp, "sipp");
    for suffix in ["_.csv", "_rtt.csv", "_counts.csv"] {
        let ours = stat_file_header(&sipr_dir, suffix);
        let theirs = stat_file_header(&sipp_dir, suffix);
        assert_eq!(ours, theirs, "{suffix} header differs");
        assert!(!ours.is_empty(), "{suffix} header empty");
    }
    for dir in [&sipr_dir, &sipp_dir] {
        for suffix in ["_.csv", "_counts.csv"] {
            let name = std::fs::read_dir(dir)
                .expect("readdir")
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .find(|n| n.ends_with(suffix))
                .expect("file");
            let text = std::fs::read_to_string(dir.join(name)).expect("read");
            let mut lines = text.lines();
            let header = lines.next().expect("header");
            for row in lines {
                assert_eq!(
                    row.matches(';').count(),
                    header.matches(';').count(),
                    "{}: {suffix} row width:\n{row}",
                    dir.display()
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&sipr_dir);
    let _ = std::fs::remove_dir_all(&sipp_dir);
}
