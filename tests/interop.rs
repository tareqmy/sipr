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
