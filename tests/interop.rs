//! Interop suite: sipr against a REAL SIPp binary (docs/TESTING.md §4).
//!
//! Locating sipp: `$SIPP_BIN`, then `sipp` on PATH. When neither exists the
//! tests print a VISIBLE skip marker and pass vacuously — a green run that
//! executed nothing must be distinguishable in the log (never silent).

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{SpawnOutsideProbes, free_even_port, free_port, free_port_block};

fn sipp_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SIPP_BIN") {
        // Absolute, because tests start sipp in a tempdir: a relative
        // `SIPP_BIN=../../cprojects/sipp/sipp` would resolve from there.
        let p = std::fs::canonicalize(p).ok().filter(|p| p.is_file());
        if p.is_some() {
            return p;
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("sipp"))
        .find(|c| c.is_file())
}

/// A command for `program`, real sipp or sipr, with `-nostdin`. A sipp whose
/// stdin is /dev/null busy-polls it at a full core, mostly kernel time
/// (`-bg` does not help: its forked child points stdin at /dev/null too),
/// and a suite's worth of them skews every test's timings. sipr takes the
/// flag too. Start every sipp and sipr through this.
fn tool_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.arg("-nostdin");
    command
}

/// Whether this sipp build has TLS compiled in (`sipp -v` banners `-TLS`).
fn sipp_supports_tls(sipp: &std::path::Path) -> bool {
    Command::new(sipp)
        .arg("-v")
        .output_outside_probes()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("TLS"))
}

/// Whether a sipp error log in `dir` shows the stream-client bind failure
/// (sipp binds its connect socket onto its own listening port; macOS refuses
/// with EADDRINUSE where Linux's SO_REUSEADDR semantics allow it).
fn sipp_stream_client_cannot_bind(dir: &std::path::Path) -> bool {
    sipp_error_log_contains(dir, "Unable to bind TCP socket")
}

/// Whether sipp tripped over its own use-after-free on a reset TCP
/// connection (`socket.cpp` ~l.2151: the `SIPpSocket` it sends on has been
/// freed, so `ss_transport` reads back as garbage). It shows up two ways,
/// both diagnostic and both seen on macOS with sipp 3.7.7: the fatal
/// `default:` arm of `write_primitive` ("Internal error, unknown transport
/// type 1024"), or "Unable to send UDP message" on a run that is `-t t1`
/// throughout and has no UDP socket at all — after which sipp can spin past
/// its own `-timeout`. Nothing sipr does can prevent it: closing the
/// connection is the point of the test. So the test skips visibly rather
/// than failing on sipp's bug (docs/SIPP_COMPAT.md §6).
fn sipp_freed_socket_on_reset(dir: &std::path::Path) -> bool {
    sipp_error_log_contains(dir, "unknown transport type")
        || sipp_error_log_contains(dir, "Unable to send UDP message")
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
    let sipp_child = tool_command(&sipp)
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
        .spawn_outside_probes();
    // Some sipp builds daemonize with -bg; retry plain if spawn failed.
    let mut sipp_proc = match sipp_child {
        Ok(c) => Reaper(c),
        Err(e) => panic!("cannot spawn sipp: {e}"),
    };
    // Give the UAS a moment to bind.
    std::thread::sleep(Duration::from_millis(300));

    let mut sipr_proc = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipp_uac = Reaper(
        tool_command(&sipp)
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("cannot spawn sipp"),
    );
    // Give the UAS a moment to bind before sipr dials its TLS connection.
    std::thread::sleep(Duration::from_millis(300));

    let mut sipr_proc = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    // sipp's stream-transport client bind does not walk past an occupied
    // default port (unlike UDP), so hand it a known-free local port.
    let uac_port = free_port();
    let log_dir = tempfile::tempdir().expect("sipp log dir");
    let mut sipp_uac = Reaper(
        tool_command(&sipp)
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_proc = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_proc = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_proc = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_proc = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    // sipp's -rtpcheck_debug file lands in its working directory.
    let mut sipp_uac = Reaper(
        tool_command(&sipp)
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
            .spawn_outside_probes()
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
        tool_command(uas_bin)
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
            .spawn_outside_probes()
            .expect("spawn uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut uac = Reaper(
        tool_command(uac_bin)
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
            .spawn_outside_probes()
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
        tool_command(uas_bin)
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
            .spawn_outside_probes()
            .expect("spawn uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let started = std::time::Instant::now();
    let mut uac = Reaper(
        tool_command(uac_bin)
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_uac = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
            tool_command(env!("CARGO_BIN_EXE_sipr"))
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
                .spawn_outside_probes()
                .expect("spawn sipr uas"),
        );
        std::thread::sleep(Duration::from_millis(300));
        let mut sipp_uac = Reaper(
            tool_command(&sipp)
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
                .spawn_outside_probes()
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
            tool_command(bin)
                .current_dir(&dir)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn_outside_probes()
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
            tool_command(uas_bin)
                .current_dir(cwd)
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn_outside_probes()
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
        tool_command(uac_bin)
            .current_dir(cwd)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn_outside_probes()
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
    if code != Some(1) && sipp_freed_socket_on_reset(dir.path()) {
        eprintln!(
            "SKIPPED interop::real_sipp_tcp_uac_reconnects_to_sipr — sipp tripped over its \
             own use-after-free on the reset connection (socket.cpp ~l.2151): it either \
             died on the fatal 'unknown transport type' or spun past its -timeout."
        );
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
            tool_command(bin)
                .current_dir(dir.path())
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn_outside_probes()
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
        .output_outside_probes()
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
            tool_command(bin)
                .current_dir(dir.path())
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn_outside_probes()
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
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipp_uac = Reaper(
        tool_command(&sipp)
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_uac = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp mixed"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_mixed = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipr_mixed = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
            .expect("spawn sipr mixed"),
    );
    std::thread::sleep(Duration::from_millis(300));
    let mut sipp_uac = Reaper(
        tool_command(&sipp)
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
            .spawn_outside_probes()
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
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipp_uac = Reaper(
        tool_command(&sipp)
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_uac = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
            .expect("spawn sipr uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipp_uac = Reaper(
        tool_command(&sipp)
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
            .spawn_outside_probes()
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
        tool_command(&sipp)
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
            .spawn_outside_probes()
            .expect("spawn sipp uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut sipr_uac = Reaper(
        tool_command(env!("CARGO_BIN_EXE_sipr"))
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
            .spawn_outside_probes()
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
        tool_command(bin)
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
            .spawn_outside_probes()
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
            tool_command(uac_bin)
                .current_dir(dir.path())
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn_outside_probes()
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
            tool_command(uac_bin)
                .current_dir(dir.path())
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .stdin(Stdio::null())
                .spawn_outside_probes()
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
        tool_command(uas_bin)
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
            .spawn_outside_probes()
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
        tool_command(uac_bin)
            .current_dir(&dir)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn_outside_probes()
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
        tool_command(uas_bin)
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
            .spawn_outside_probes()
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
        tool_command(uac_bin)
            .current_dir(&dir)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
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

// ---- M41: message and error logs ---------------------------------------

/// The `-trace_shortmsg` lines of every `*_shortmessages.log` in `dir`,
/// reduced to (direction, start line) pairs, distinct, sorted.
fn short_message_shapes(dir: &std::path::Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .ends_with("_shortmessages.log")
        {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
        for line in text.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            // A time in the default form holds two tabs of its own.
            let (dir, start) = match cols.len() {
                7 => (cols[3], cols[6]),
                5 => (cols[1], cols[4]),
                _ => panic!("unexpected short message line: {line}"),
            };
            // Each run's UAS listens on its own port, which the request
            // URIs carry: compare with the port masked.
            let start = match start.rsplit_once(':') {
                Some((head, tail)) if tail.starts_with(|c: char| c.is_ascii_digit()) => {
                    let port_len = tail.bytes().take_while(u8::is_ascii_digit).count();
                    format!("{head}:PORT{}", &tail[port_len..])
                }
                _ => start.to_owned(),
            };
            let pair = (dir.to_owned(), start);
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
    }
    out.sort();
    out
}

/// `-trace_shortmsg` at parity: sipr and real sipp run the same embedded
/// UAC against the other's UAS and log the same set of (S|R, start line)
/// pairs, one tab-separated line per message in SIPp's field layout.
#[test]
fn short_message_log_matches_real_sipps() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::short_message_log_matches_real_sipps — no sipp.");
        return;
    };
    let sipr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let run = |uas_bin: &std::path::Path, uac_bin: &std::path::Path, tag: &str| {
        let dir = std::env::temp_dir().join(format!(
            "sipr-interop-shortmsg-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let port = free_port();
        let mut uas = Reaper(
            tool_command(uas_bin)
                .current_dir(&dir)
                .args([
                    "-sn",
                    "uas",
                    "-i",
                    "127.0.0.1",
                    "-p",
                    &port.to_string(),
                    "-m",
                    "2",
                    "-timeout",
                    "30",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn_outside_probes()
                .expect("spawn uas"),
        );
        std::thread::sleep(Duration::from_millis(400));
        let mut args: Vec<String> = [
            "-sn",
            "uac",
            "-i",
            "127.0.0.1",
            "-r",
            "10",
            "-m",
            "2",
            "-d",
            "50",
            "-timeout",
            "20",
            "-trace_shortmsg",
        ]
        .iter()
        .map(|a| (*a).to_owned())
        .collect();
        if uac_bin == std::path::Path::new(env!("CARGO_BIN_EXE_sipr")) {
            args.push("-bg".to_owned());
        }
        args.push(format!("127.0.0.1:{port}"));
        let mut uac = Reaper(
            tool_command(uac_bin)
                .current_dir(&dir)
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn_outside_probes()
                .expect("spawn uac"),
        );
        let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
        let _ = wait_with_timeout(&mut uas.0, Duration::from_secs(15));
        (dir, code)
    };
    let (sipr_dir, sipr_code) = run(&sipp, &sipr, "sipr");
    assert_eq!(sipr_code, Some(0), "sipr uac");
    let (sipp_dir, _) = run(&sipr, &sipp, "sipp");
    let ours = short_message_shapes(&sipr_dir);
    let theirs = short_message_shapes(&sipp_dir);
    assert!(!ours.is_empty(), "sipr wrote no short messages");
    assert_eq!(
        ours, theirs,
        "short message (direction, start line) sets differ"
    );
    let _ = std::fs::remove_dir_all(&sipr_dir);
    let _ = std::fs::remove_dir_all(&sipp_dir);
}

// ---- M42: timer knobs -------------------------------------------------

/// The INVITE frames in a `-trace_msg` log (first send + retransmissions).
fn invites_sent_in_message_log(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with("_messages.log"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .map(|log| log.matches("\nINVITE sip:").count())
        .sum()
}

/// `-max_invite_retrans 2` against a peer that never answers: sipr and
/// real sipp both send the INVITE three times (once plus two
/// retransmissions) and give the call up within the same few seconds.
#[test]
fn max_invite_retrans_counts_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::max_invite_retrans_counts_like_real_sipp — no sipp.");
        return;
    };
    let sipr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let dead = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let target = dead.local_addr().expect("addr").to_string();
    drop(dead);
    let run = |bin: &std::path::Path, tag: &str| -> (usize, Duration) {
        let dir =
            std::env::temp_dir().join(format!("sipr-interop-retrans-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut args: Vec<String> = [
            "-sn",
            "uac",
            "-i",
            "127.0.0.1",
            "-m",
            "1",
            "-max_invite_retrans",
            "2",
            "-timeout",
            "20",
            "-trace_msg",
        ]
        .iter()
        .map(|a| (*a).to_owned())
        .collect();
        if bin == std::path::Path::new(env!("CARGO_BIN_EXE_sipr")) {
            args.push("-bg".to_owned());
        }
        args.push(target.clone());
        let started = std::time::Instant::now();
        let mut child = Reaper(
            tool_command(bin)
                .current_dir(&dir)
                .args(&args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn_outside_probes()
                .expect("spawn"),
        );
        let _ = wait_with_timeout(&mut child.0, Duration::from_secs(25));
        let elapsed = started.elapsed();
        let invites = invites_sent_in_message_log(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        (invites, elapsed)
    };
    let (ours, our_time) = run(&sipr, "sipr");
    let (theirs, their_time) = run(&sipp, "sipp");
    assert_eq!(ours, 3, "sipr: one INVITE plus two retransmissions");
    assert_eq!(theirs, 3, "sipp: one INVITE plus two retransmissions");
    // 500 ms + 1 s before the third send, then one more interval to give
    // up: both finish in a few seconds, not SIPp's default ~12.
    assert!(our_time < Duration::from_secs(8), "sipr took {our_time:?}");
    assert!(
        their_time < Duration::from_secs(8),
        "sipp took {their_time:?}"
    );
}

fn ext3pcc_master_xml() -> String {
    format!(
        r#"{SIPP_XML_HEADER}<scenario name="3pcc extended master">
  <send retrans="500"><![CDATA[
    INVITE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: m <sip:m@[local_ip]:[local_port]>;tag=[pid]m[call_number]
    To: svc <sip:svc@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:m@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200">
    <action><ereg regexp="Content-Type:.*" search_in="msg" assign_to="1"/></action>
  </recv>
  <sendCmd dest="s1"><![CDATA[
    Call-ID: [call_id]
    From: m
    [$1]
  ]]></sendCmd>
  <recvCmd src="s1">
    <action><ereg regexp="Content-Type:.*" search_in="msg" assign_to="2"/></action>
  </recvCmd>
  <send><![CDATA[
    ACK sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: m <sip:m@[local_ip]:[local_port]>;tag=[pid]m[call_number]
    To: svc <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Contact: sip:m@[local_ip]:[local_port]
    Max-Forwards: 70
    X-Answer: [$2]
    Content-Length: 0

  ]]></send>
  <pause milliseconds="700"/>
  <send retrans="500"><![CDATA[
    BYE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: m <sip:m@[local_ip]:[local_port]>;tag=[pid]m[call_number]
    To: svc <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Contact: sip:m@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"#
    )
}

fn ext3pcc_slave_xml() -> String {
    format!(
        r#"{SIPP_XML_HEADER}<scenario name="3pcc extended slave">
  <recvCmd src="m">
    <action><ereg regexp="Content-Type:.*" search_in="msg" assign_to="1"/></action>
  </recvCmd>
  <send retrans="500"><![CDATA[
    INVITE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: s1 <sip:s1@[local_ip]:[local_port]>;tag=[pid]s1[call_number]
    To: svc <sip:svc@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:s1@[local_ip]:[local_port]
    Max-Forwards: 70
    X-Offer: [$1]
    Content-Length: 0

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200">
    <action><ereg regexp="Content-Type:.*" search_in="msg" assign_to="2"/></action>
  </recv>
  <send><![CDATA[
    ACK sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: s1 <sip:s1@[local_ip]:[local_port]>;tag=[pid]s1[call_number]
    To: svc <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Contact: sip:s1@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <sendCmd dest="m"><![CDATA[
    Call-ID: [call_id]
    From: s1
    [$2]
  ]]></sendCmd>
  <pause milliseconds="100"/>
  <send retrans="500"><![CDATA[
    BYE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: s1 <sip:s1@[local_ip]:[local_port]>;tag=[pid]s1[call_number]
    To: svc <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Contact: sip:s1@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"#
    )
}

/// One extended-3PCC run: two sipr UASes (one per leg), the slave started
/// first and without `-m` (a closed twin aborts whatever is still open, so
/// the master's end is what stops it), the master last with `-m 1` (SIPp's
/// rule: the master dials the slaves). Returns (master exit, slave exit,
/// master stderr, slave stderr).
fn run_ext3pcc_pair(
    master_bin: &std::path::Path,
    slave_bin: &std::path::Path,
    tag: &str,
) -> (Option<i32>, Option<i32>, String, String) {
    let sipr = std::path::Path::new(env!("CARGO_BIN_EXE_sipr"));
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let cfg_path = dir.join(format!("sipr-interop-ext3pcc-{tag}-{pid}.cfg"));
    let master_path = dir.join(format!("sipr-interop-ext3pcc-master-{tag}-{pid}.xml"));
    let slave_path = dir.join(format!("sipr-interop-ext3pcc-slave-{tag}-{pid}.xml"));
    let (pm, p1) = (free_port(), free_port());
    std::fs::write(&cfg_path, format!("m;127.0.0.1:{pm}\ns1;127.0.0.1:{p1}\n")).expect("write cfg");
    std::fs::write(&master_path, ext3pcc_master_xml()).expect("write master");
    std::fs::write(&slave_path, ext3pcc_slave_xml()).expect("write slave");
    let cfg = cfg_path.to_str().expect("utf8").to_owned();
    // One UAS per leg: the two legs share the master's Call-ID.
    let spawn_uas = |port: u16| {
        Reaper(
            tool_command(sipr)
                .current_dir(&dir)
                .args([
                    "-sn",
                    "uas",
                    "-i",
                    "127.0.0.1",
                    "-p",
                    &port.to_string(),
                    "-m",
                    "1",
                    "-timeout",
                    "40",
                    "-bg",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .spawn_outside_probes()
                .expect("spawn uas"),
        )
    };
    let (uas_a, uas_b) = (free_port(), free_port());
    let _uas_a = spawn_uas(uas_a);
    let _uas_b = spawn_uas(uas_b);
    std::thread::sleep(Duration::from_millis(300));
    let spawn_peer =
        |bin: &std::path::Path, scenario: &std::path::Path, role: &str, name: &str, uas: u16| {
            let mut args = vec![
                "-sf".to_owned(),
                scenario.to_str().expect("utf8").to_owned(),
                "-i".to_owned(),
                "127.0.0.1".to_owned(),
                role.to_owned(),
                name.to_owned(),
                "-slave_cfg".to_owned(),
                cfg.clone(),
                "-timeout".to_owned(),
                "30".to_owned(),
            ];
            if role == "-master" {
                args.extend(["-m".to_owned(), "1".to_owned()]);
            }
            if bin == sipr {
                args.push("-bg".to_owned());
            }
            args.push(format!("127.0.0.1:{uas}"));
            Reaper(
                tool_command(bin)
                    .current_dir(&dir)
                    .args(&args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .stdin(Stdio::null())
                    .spawn_outside_probes()
                    .expect("spawn peer"),
            )
        };
    let mut slave = spawn_peer(slave_bin, &slave_path, "-slave", "s1", uas_b);
    std::thread::sleep(Duration::from_millis(600));
    let mut master = spawn_peer(master_bin, &master_path, "-master", "m", uas_a);
    let master_code = wait_with_timeout(&mut master.0, Duration::from_secs(25));
    let master_err = child_stderr(&mut master.0);
    let slave_code = wait_with_timeout(&mut slave.0, Duration::from_secs(15));
    let slave_err = child_stderr(&mut slave.0);
    for p in [&cfg_path, &master_path, &slave_path] {
        let _ = std::fs::remove_file(p);
    }
    (master_code, slave_code, master_err, slave_err)
}

/// Extended 3PCC both ways: a sipr master drives a real sipp slave, then a
/// real sipp master drives a sipr slave, on SIPp's documented
/// `-master`/`-slave`/`-slave_cfg` + `dest=`/`src=` form (the master's
/// Content-Type travels to the slave's INVITE and the slave's back into
/// the master's ACK, as in `docs/3PCC_extended.rst`).
#[test]
fn extended_3pcc_both_ways_against_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("skipping: no sipp binary");
        return;
    };
    let sipr = std::path::Path::new(env!("CARGO_BIN_EXE_sipr"));
    let (m, s, m_err, s_err) = run_ext3pcc_pair(sipr, &sipp, "siprmaster");
    assert_eq!(m, Some(0), "sipr master:\n{m_err}\nsipp slave:\n{s_err}");
    assert!(
        m_err.contains("successful 1 failed 0"),
        "sipr master:\n{m_err}"
    );
    assert_eq!(s, Some(0), "sipp slave:\n{s_err}\nsipr master:\n{m_err}");
    let (m, s, m_err, s_err) = run_ext3pcc_pair(&sipp, sipr, "sippmaster");
    assert_eq!(s, Some(0), "sipr slave:\n{s_err}\nsipp master:\n{m_err}");
    assert!(
        s_err.contains("successful 1 failed 0"),
        "sipr slave:\n{s_err}"
    );
    assert_eq!(m, Some(0), "sipp master:\n{m_err}\nsipr slave:\n{s_err}");
}

// ---- message indices: labels are not messages ---------------------------

/// A UAC whose jumps cross labels. Every `<send>` names itself in
/// `X-Landed` next to its `[msg_index]`, and carries `[branch]` in its Via.
/// SIPp numbers messages, not labels: message 0 jumps to 3 (`value=`), 4
/// jumps to 7 (`variable=`, set by an `add` to the unset variable), so only
/// `target-a` and `target-b` go out.
fn jump_over_labels_uac_xml() -> String {
    let send = |name: &str| {
        format!(
            r"  <send><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 OPTIONS
    Max-Forwards: 70
    X-Landed: {name} [msg_index]
    Content-Length: 0

  ]]></send>
"
        )
    };
    format!(
        r#"<scenario name="jump-over-labels">
  <nop><action><jump value="3"/></action></nop>
  <label id="a"/>
{skipped1}{skipped2}  <label id="b"/>
{target_a}  <nop>
    <action>
      <add assign_to="back" value="7"/>
      <jump variable="back"/>
    </action>
  </nop>
{skipped3}{skipped4}  <label id="c"/>
{target_b}</scenario>
"#,
        skipped1 = send("skipped-1"),
        skipped2 = send("skipped-2"),
        target_a = send("target-a"),
        skipped3 = send("skipped-3"),
        skipped4 = send("skipped-4"),
        target_b = send("target-b"),
    )
}

/// Run `uac_bin` on [`jump_over_labels_uac_xml`] against a UDP sink. Returns
/// the exit code, what the sink saw (`X-Landed` value plus the Via branch's
/// message-index suffix, retransmissions collapsed) and the `-trace_counts`
/// header's columns, whose index prefixes are what a label would shift.
fn run_jump_over_labels(
    uac_bin: &std::path::Path,
    tag: &str,
) -> (Option<i32>, Vec<String>, Vec<String>) {
    let dir = std::env::temp_dir().join(format!("sipr-interop-jump-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let xml = dir.join("jump_over_labels.xml");
    std::fs::write(&xml, jump_over_labels_uac_xml()).expect("write uac");
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let mut args = vec![
        "-sf".to_owned(),
        xml.to_str().expect("utf8").to_owned(),
        "-i".to_owned(),
        "127.0.0.1".to_owned(),
        "-m".to_owned(),
        "1".to_owned(),
        "-timeout".to_owned(),
        "20".to_owned(),
        "-trace_counts".to_owned(),
    ];
    if uac_bin == std::path::Path::new(env!("CARGO_BIN_EXE_sipr")) {
        args.push("-bg".to_owned());
    }
    args.push(sink.local_addr().expect("sink addr").to_string());
    let mut uac = Reaper(
        tool_command(uac_bin)
            .current_dir(&dir)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    // The run is over: everything it sent is queued on the sink.
    sink.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut seen: Vec<String> = Vec::new();
    let mut buf = [0u8; 65_535];
    while let Ok(n) = sink.recv(&mut buf) {
        let text = String::from_utf8_lossy(&buf[..n]);
        let header = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(name))
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        let branch = header("Via:");
        let branch_index = branch.rsplit('-').next().unwrap_or_default().to_owned();
        let entry = format!("{} {branch_index}", header("X-Landed:"));
        if seen.last() != Some(&entry) {
            seen.push(entry);
        }
    }
    let counts = stat_file_header(&dir, "_counts.csv")
        .split(';')
        .map(ToOwned::to_owned)
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    (code, seen, counts)
}

/// `<jump value=>`, `<jump variable=>`, `[msg_index]`, `[branch]` and the
/// `-trace_counts` column names all count SIPp messages, which labels are
/// not (docs/SIPP_COMPAT.md §6): the same UAC sends the same messages, with
/// the same indices, under sipr and real sipp.
#[test]
fn jumps_and_message_indices_skip_labels_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::jumps_and_message_indices_skip_labels_like_real_sipp — no sipp."
        );
        return;
    };
    let (code, theirs, their_counts) = run_jump_over_labels(&sipp, "sipp");
    assert_eq!(code, Some(0), "real sipp uac");
    assert_eq!(theirs, ["target-a 3 3", "target-b 7 7"], "real sipp");
    assert_eq!(
        their_counts.get(..5).unwrap_or_default(),
        [
            "CurrentTime",
            "ElapsedTime",
            "0_Pause_Sessions",
            "0_Pause_Unexp",
            "1_OPTIONS_Sent"
        ],
        "real sipp: a nop gets the Pause columns"
    );
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let (code, ours, our_counts) = run_jump_over_labels(&sipr, "sipr");
    assert_eq!(code, Some(0), "sipr uac");
    assert_eq!(ours, theirs, "sipr sent different messages than real sipp");
    assert_eq!(our_counts, their_counts, "-trace_counts columns differ");
}

// ---- where a <jump> lands: SIPp's next() after msg_index = N - 1 ---------

/// A UAC whose jumps land where SIPp's `next()` puts them. Messages: 0 a
/// nop jumping to 4 then setting `late` (the actions after a jump run),
/// 1-4 sends, of which 3 has `next="tail"`, so the jump to 4 follows it
/// (`msg_index = 3`); 5 a nop jumping to 7 then 8 (the last jump wins),
/// 6-8 sends, 8 with a jump to 10 that runs after it is sent; 9, 10 sends.
fn jump_resume_uac_xml() -> String {
    let send = |step: &str, attrs: &str, actions: &str| {
        format!(
            r"  <send{attrs}><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:jump@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 OPTIONS
    Max-Forwards: 70
    X-Step: {step} [$late]
    Content-Length: 0

  ]]>{actions}</send>
"
        )
    };
    format!(
        r#"<scenario name="jump-resume">
  <nop><action><jump value="4"/><assignstr assign_to="late" value="ran"/></action></nop>
{s1}{s2}{s3}{s4}  <label id="tail"/>
  <nop><action><jump value="7"/><jump value="8"/></action></nop>
{s6}{s7}{s8}{s9}{s10}</scenario>
"#,
        s1 = send("skipped-1", "", ""),
        s2 = send("skipped-2", "", ""),
        s3 = send("skipped-3", r#" next="tail""#, ""),
        s4 = send("target-4", "", ""),
        s6 = send("skipped-6", "", ""),
        s7 = send("skipped-7", "", ""),
        s8 = send("landed-8", "", r#"<action><jump value="10"/></action>"#),
        s9 = send("skipped-9", "", ""),
        s10 = send("final-10", "", ""),
    )
}

/// Run `uac_bin` on [`jump_resume_uac_xml`] against a UDP sink. Returns its
/// exit code and the `X-Step`s the sink got, retransmissions collapsed.
fn run_jump_resume_uac(uac_bin: &std::path::Path) -> (Option<i32>, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let xml = dir.path().join("jump_resume.xml");
    std::fs::write(&xml, jump_resume_uac_xml()).expect("write uac");
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let target = sink.local_addr().expect("sink addr").to_string();
    let mut uac = Reaper(
        tool_command(uac_bin)
            .current_dir(dir.path())
            .args(["-sf", xml.to_str().expect("utf8")])
            .args(["-i", "127.0.0.1", "-m", "1", "-timeout", "20"])
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    sink.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut seen: Vec<String> = Vec::new();
    let mut buf = [0u8; 65_535];
    while let Ok(n) = sink.recv(&mut buf) {
        let step = String::from_utf8_lossy(&buf[..n])
            .lines()
            .find_map(|l| l.strip_prefix("X-Step:"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        if seen.last() != Some(&step) {
            seen.push(step);
        }
    }
    (code, seen)
}

/// A `<jump>` to message N sets SIPp's `msg_index` to N - 1 and leaves the
/// rest to `next()` (docs/SIPP_COMPAT.md §6): message N-1's `next=` wins
/// over N, the actions after a jump still run, the last jump wins, and a
/// send's jump runs after the send.
#[test]
fn jumps_resume_through_next_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::jumps_resume_through_next_like_real_sipp — no sipp.");
        return;
    };
    let (code, theirs) = run_jump_resume_uac(&sipp);
    assert_eq!(code, Some(0), "real sipp uac");
    assert_eq!(theirs, ["landed-8 ran", "final-10 ran"], "real sipp");
    let (code, ours) = run_jump_resume_uac(&PathBuf::from(env!("CARGO_BIN_EXE_sipr")));
    assert_eq!(code, Some(0), "sipr uac");
    assert_eq!(ours, theirs, "sipr sent different messages than real sipp");
}

/// The 200 a recv-jump UAS answers with, its `X-Step` naming where the call
/// has got to.
fn step_200(step: &str) -> String {
    format!(
        r"  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]SIPpTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    X-Step: {step}
    Content-Length: 0

  ]]></send>
"
    )
}

/// An optional INFO that stays where the call waited (its `next=`'s `test=`
/// variable is left unset) and jumps to message `target` from its actions.
fn staying_info(attrs: &str, target: usize) -> String {
    format!(
        r#"  <recv request="INFO" optional="true" next="never" test="miss"{attrs}>
    <action>
      <ereg regexp="no-such-text" search_in="msg" assign_to="miss"/>
      <jump value="{target}"/>
    </action>
  </recv>
"#
    )
}

/// Run `uas_bin` on `xml` and drive it from a raw UDP UAC: each request of
/// `script` in turn (the first resent until the UAS answers), listening its
/// duration for the `X-Step`s the UAS sends back. Returns the exit code and
/// one `METHOD: steps` line per request.
fn run_scripted_uas(
    uas_bin: &std::path::Path,
    xml: &str,
    script: &[(&str, Duration)],
) -> (Option<i32>, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("scripted_uas.xml");
    std::fs::write(&path, xml).expect("write uas");
    let port = free_port();
    let mut uas = Reaper(
        tool_command(uas_bin)
            .current_dir(dir.path())
            .args(["-sf", path.to_str().expect("utf8")])
            .args(["-i", "127.0.0.1", "-p", &port.to_string()])
            .args(["-m", "1", "-timeout", "10"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uas"),
    );
    let uas_addr = format!("127.0.0.1:{port}");
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uac");
    let local = sock.local_addr().expect("uac addr");
    let request = |method: &str, cseq: usize| {
        format!(
            "{method} sip:svc@{uas_addr} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {local};branch=z9hG4bK-scripted-{cseq}\r\n\
             From: <sip:uac@{local}>;tag=scripted-uac\r\n\
             To: <sip:svc@{uas_addr}>\r\n\
             Call-ID: scripted-{}@127.0.0.1\r\n\
             CSeq: {cseq} {method}\r\n\
             Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
            local.port()
        )
    };
    let mut buf = [0u8; 65_535];
    let mut listen = |limit: Duration| {
        let mut steps: Vec<String> = Vec::new();
        let start = Instant::now();
        while let Some(left) = limit.checked_sub(start.elapsed()) {
            sock.set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .expect("timeout");
            let Ok(n) = sock.recv(&mut buf) else {
                break;
            };
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            if let Some(step) = text.lines().find_map(|l| l.strip_prefix("X-Step:")) {
                let step = step.trim().to_owned();
                if steps.last() != Some(&step) {
                    steps.push(step);
                }
            }
        }
        steps
    };
    let mut transcript = Vec::new();
    for (cseq, &(method, limit)) in script.iter().enumerate() {
        let tries = if cseq == 0 { 10 } else { 1 };
        let mut steps = Vec::new();
        for _ in 0..tries {
            sock.send_to(request(method, cseq + 1).as_bytes(), &uas_addr)
                .expect("send request");
            steps = listen(limit);
            if !steps.is_empty() {
                break;
            }
        }
        transcript.push(format!("{method}: {}", steps.join(" ")));
    }
    let code = wait_with_timeout(&mut uas.0, Duration::from_secs(12));
    (code, transcript)
}

/// A `<jump>` among a recv's actions, as SIPp's `process_incoming` treats
/// it (docs/SIPP_COMPAT.md §6): a mandatory recv's `next()` overwrites it,
/// and an optional recv that stays keeps it, so the call waits at message
/// N-1. Two UASes: one where that message is a recv, which then takes the
/// next request; one where it is a send, which the stayed recv's
/// `timeout=` deadline wakes the call to run.
#[test]
fn jumps_in_a_recvs_actions_follow_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::jumps_in_a_recvs_actions_follow_real_sipp — no sipp.");
        return;
    };
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let short = Duration::from_millis(400);
    // 0 OPTIONS, 1 its 200, 2 INFO (stays; jump to 5 waits at 4),
    // 3 BYE, 4 MESSAGE, 5 its 200.
    let waits_at_a_recv = format!(
        r#"<scenario name="recv-jump-to-recv">
  <recv request="OPTIONS"><action><jump value="3"/></action></recv>
{answered}{info}  <recv request="BYE"/>
  <recv request="MESSAGE"/>
{messaged}  <label id="never"/>
</scenario>
"#,
        answered = step_200("after-options"),
        info = staying_info("", 5),
        messaged = step_200("after-message"),
    );
    let script = [("OPTIONS", short), ("INFO", short), ("MESSAGE", short)];
    let (code, theirs) = run_scripted_uas(&sipp, &waits_at_a_recv, &script);
    assert_eq!(code, Some(0), "real sipp uas");
    assert_eq!(
        theirs,
        ["OPTIONS: after-options", "INFO: ", "MESSAGE: after-message"],
        "real sipp"
    );
    let (code, ours) = run_scripted_uas(&sipr, &waits_at_a_recv, &script);
    assert_eq!(code, Some(0), "sipr uas");
    assert_eq!(ours, theirs, "sipr answered differently than real sipp");

    // 0 OPTIONS, 1 its 200, 2 INFO (stays, timeout 1 s; jump to 5 waits at
    // 4), 3 BYE, 4 the 200 the deadline sends, 5 BYE, 6 its 200.
    let waits_at_a_send = format!(
        r#"<scenario name="recv-jump-to-send">
  <recv request="OPTIONS"/>
{answered}{info}  <recv request="BYE"/>
{woken}  <recv request="BYE"/>
{byed}  <label id="never"/>
</scenario>
"#,
        answered = step_200("after-options"),
        info = staying_info(r#" timeout="1000""#, 5),
        woken = step_200("woken"),
        byed = step_200("after-bye"),
    );
    let script = [
        ("OPTIONS", short),
        ("INFO", Duration::from_millis(1600)),
        ("BYE", short),
    ];
    let (code, theirs) = run_scripted_uas(&sipp, &waits_at_a_send, &script);
    assert_eq!(code, Some(0), "real sipp uas");
    assert_eq!(
        theirs,
        ["OPTIONS: after-options", "INFO: woken", "BYE: after-bye"],
        "real sipp"
    );
    let (code, ours) = run_scripted_uas(&sipr, &waits_at_a_send, &script);
    assert_eq!(code, Some(0), "sipr uas");
    assert_eq!(ours, theirs, "sipr answered differently than real sipp");
}

// ---- [msg_index] and [branch] where SIPp renders with no message index ---

/// A UAC rendering `[msg_index]` and `[branch]`, offsets included, in a
/// nop's `<log>`, in a send and that send's `<log>`, and through an
/// `<assignstr>`. Messages: 0 nop, 1 send (behind a label, which does not
/// count), 2 nop.
const MSG_INDEX_UAC_XML: &str = r#"<scenario name="msg-index">
  <nop><action><log message="nop0 [msg_index] [branch] [branch-1] [branch+2]"/></action></nop>
  <label id="l"/>
  <send><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:idx@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 OPTIONS
    Max-Forwards: 70
    X-Index: [msg_index] [branch-1] [branch+1]
    Content-Length: 0

  ]]><action><log message="send1 [msg_index] [branch]"/></action></send>
  <nop><action><assignstr assign_to="s" value="[msg_index] [branch]"/><log message="nop2 [$s]"/></action></nop>
</scenario>
"#;

/// `text` with the pid in every `z9hG4bK-<pid>-` branch masked, since the
/// two tools run as different processes.
fn mask_branch_pids(text: &str) -> String {
    let mut parts = text.split("z9hG4bK-");
    let mut out = parts.next().unwrap_or_default().to_owned();
    for part in parts {
        out.push_str("z9hG4bK-PID");
        out.push_str(part.trim_start_matches(|c: char| c.is_ascii_digit()));
    }
    out
}

/// Run `uac_bin` on [`MSG_INDEX_UAC_XML`] against a UDP sink with
/// `-trace_logs`. Returns its exit code, then the `X-Index` of the OPTIONS
/// followed by the log lines, branch pids masked.
fn run_msg_index_uac(uac_bin: &std::path::Path) -> (Option<i32>, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let xml = dir.path().join("msg_index.xml");
    std::fs::write(&xml, MSG_INDEX_UAC_XML).expect("write uac");
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let target = sink.local_addr().expect("sink addr").to_string();
    let mut uac = Reaper(
        tool_command(uac_bin)
            .current_dir(dir.path())
            .args(["-sf", xml.to_str().expect("utf8")])
            .args(["-i", "127.0.0.1", "-m", "1", "-timeout", "20"])
            .arg("-trace_logs")
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    sink.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut buf = [0u8; 65_535];
    let sent = sink.recv(&mut buf).map_or_else(
        |_| "<nothing sent>".to_owned(),
        |n| {
            String::from_utf8_lossy(&buf[..n])
                .lines()
                .find(|l| l.starts_with("X-Index:"))
                .unwrap_or("<no X-Index>")
                .to_owned()
        },
    );
    let logs = std::fs::read_dir(dir.path())
        .expect("readdir")
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().ends_with("_logs.log"))
        .map(|e| std::fs::read_to_string(e.path()).expect("read logs"))
        .unwrap_or_default();
    let lines = std::iter::once(sent.as_str())
        .chain(logs.lines())
        .map(mask_branch_pids)
        .collect();
    (code, lines)
}

/// SIPp renders action messages with no message index (`P_index` -1):
/// `[msg_index]` prints -1 and `[branch]` ends in the call's message index
/// minus one. A send renders its own index, and `[branch±N]` offsets apply
/// either way (docs/SIPP_COMPAT.md §6).
#[test]
fn msg_index_and_branch_in_actions_render_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::msg_index_and_branch_in_actions_render_like_real_sipp — no sipp."
        );
        return;
    };
    let (code, theirs) = run_msg_index_uac(&sipp);
    assert_eq!(code, Some(0), "real sipp uac");
    assert_eq!(
        theirs,
        [
            "X-Index: 1 z9hG4bK-PID-1-0 z9hG4bK-PID-1-2",
            "nop0 -1 z9hG4bK-PID-1--1 z9hG4bK-PID-1--2 z9hG4bK-PID-1-1",
            "send1 -1 z9hG4bK-PID-1-0",
            "nop2 -1 z9hG4bK-PID-1-1",
        ],
        "real sipp"
    );
    let (code, ours) = run_msg_index_uac(&PathBuf::from(env!("CARGO_BIN_EXE_sipr")));
    assert_eq!(code, Some(0), "sipr uac");
    assert_eq!(ours, theirs, "sipr rendered differently than real sipp");
}

/// A 3PCC controller that sends an OPTIONS, then a twin command rendering
/// `[msg_index]` and `[branch]`: message 1, a `<sendCmd>`.
const SENDCMD_INDEX_XML: &str = r#"<scenario name="cmd-index">
  <send><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:idx@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 OPTIONS
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <sendCmd><![CDATA[
    Call-ID: [call_id]
    X-Index: [msg_index] [branch] [branch+1]
  ]]></sendCmd>
</scenario>
"#;

/// Run `bin` on [`SENDCMD_INDEX_XML`], playing the twin it dials. Returns
/// its exit code and the `X-Index` of the command it sent, branch pids
/// masked.
fn run_sendcmd_index(bin: &std::path::Path) -> (Option<i32>, String) {
    use std::io::Read;
    let dir = tempfile::tempdir().expect("tempdir");
    let xml = dir.path().join("cmd_index.xml");
    std::fs::write(&xml, SENDCMD_INDEX_XML).expect("write controller");
    let twin = TcpListener::bind("127.0.0.1:0").expect("bind twin");
    twin.set_nonblocking(true).expect("nonblocking twin");
    let twin_addr = twin.local_addr().expect("twin addr").to_string();
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let target = sink.local_addr().expect("sink addr").to_string();
    let mut controller = Reaper(
        tool_command(bin)
            .current_dir(dir.path())
            .args(["-sf", xml.to_str().expect("utf8"), "-3pcc", &twin_addr])
            .args(["-i", "127.0.0.1", "-m", "1", "-timeout", "10"])
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn controller"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match twin.accept() {
            Ok((stream, _)) => break Some(stream),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => break None,
        }
    };
    let mut command = Vec::new();
    if let Some(stream) = stream.as_mut() {
        stream.set_nonblocking(false).expect("blocking twin");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("twin timeout");
        let mut byte = [0u8; 1];
        while let Ok(1) = stream.read(&mut byte) {
            if byte[0] == 0x1b {
                break;
            }
            command.push(byte[0]);
        }
    }
    let code = wait_with_timeout(&mut controller.0, Duration::from_secs(12));
    let index = String::from_utf8_lossy(&command)
        .lines()
        .find_map(|l| l.trim().strip_prefix("X-Index:"))
        .map_or_else(|| "<no command>".to_owned(), |v| mask_branch_pids(v.trim()));
    (code, index)
}

/// A `<sendCmd>` body renders with no message index too: `[msg_index]` is
/// -1 and `[branch]` ends in the sendCmd's own index minus one.
#[test]
fn msg_index_and_branch_in_a_send_cmd_render_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::msg_index_and_branch_in_a_send_cmd_render_like_real_sipp — no sipp."
        );
        return;
    };
    let (code, theirs) = run_sendcmd_index(&sipp);
    assert_eq!(code, Some(0), "real sipp controller");
    assert_eq!(theirs, "-1 z9hG4bK-PID-1-0 z9hG4bK-PID-1-1", "real sipp");
    let (code, ours) = run_sendcmd_index(&PathBuf::from(env!("CARGO_BIN_EXE_sipr")));
    assert_eq!(code, Some(0), "sipr controller");
    assert_eq!(ours, theirs, "sipr rendered differently than real sipp");
}

/// A UAC that INVITEs, ACKs the 200, then waits 300 ms for an INFO that
/// never comes: the receive timeout fails the call, and the `bye` default
/// behavior sends SIPp's default BYE while the call is at message 3.
const ABORT_INDEX_UAC_XML: &str = r#"<scenario name="abort-index">
  <send><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:idx@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: <sip:idx@[local_ip]:[local_port]>
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:idx@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv request="INFO" timeout="300"/>
</scenario>
"#;

/// A 200 for `request`, its dialog headers mirrored and a To tag added.
fn answer_200(request: &str) -> String {
    let mut out = String::from("SIP/2.0 200 OK\r\n");
    for line in request.lines() {
        let lower = line.to_ascii_lowercase();
        if ["via:", "from:", "call-id:", "cseq:"]
            .iter()
            .any(|h| lower.starts_with(h))
        {
            out.push_str(line);
            out.push_str("\r\n");
        } else if lower.starts_with("to:") {
            out.push_str(line);
            if !lower.contains("tag=") {
                out.push_str(";tag=peer");
            }
            out.push_str("\r\n");
        }
    }
    out.push_str("Content-Length: 0\r\n\r\n");
    out
}

/// Run `uac_bin` on [`ABORT_INDEX_UAC_XML`], answering its INVITE and its
/// abort BYE. Returns its exit code and each request's method and Via
/// branch, branch pids masked.
fn run_abort_index_uac(uac_bin: &std::path::Path) -> (Option<i32>, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let xml = dir.path().join("abort_index.xml");
    std::fs::write(&xml, ABORT_INDEX_UAC_XML).expect("write uac");
    let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
    let target = peer.local_addr().expect("peer addr").to_string();
    let mut uac = Reaper(
        tool_command(uac_bin)
            .current_dir(dir.path())
            .args(["-sf", xml.to_str().expect("utf8")])
            .args(["-i", "127.0.0.1", "-m", "1", "-timeout", "10"])
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    peer.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let mut requests: Vec<String> = Vec::new();
    let mut buf = [0u8; 65_535];
    while let Ok((n, from)) = peer.recv_from(&mut buf) {
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        let method = text.split(' ').next().unwrap_or_default().to_owned();
        let branch = text
            .lines()
            .find_map(|l| l.split_once(";branch=").map(|(_, b)| b.trim()))
            .unwrap_or_default();
        let entry = format!("{method} {}", mask_branch_pids(branch));
        if requests.last() != Some(&entry) {
            requests.push(entry);
        }
        if method == "INVITE" || method == "BYE" {
            peer.send_to(answer_200(&text).as_bytes(), from)
                .expect("answer");
        }
        if method == "BYE" {
            break;
        }
    }
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(12));
    (code, requests)
}

/// The `-default_behaviors` messages render with no message index too: the
/// abort BYE's `[branch]` ends in the call's message index minus one — the
/// ACK's, here.
#[test]
fn branch_in_an_abort_bye_renders_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::branch_in_an_abort_bye_renders_like_real_sipp — no sipp.");
        return;
    };
    let (code, theirs) = run_abort_index_uac(&sipp);
    assert_eq!(code, Some(1), "real sipp uac");
    assert_eq!(
        theirs,
        [
            "INVITE z9hG4bK-PID-1-0",
            "ACK z9hG4bK-PID-1-2",
            "BYE z9hG4bK-PID-1-2"
        ],
        "real sipp"
    );
    let (code, ours) = run_abort_index_uac(&PathBuf::from(env!("CARGO_BIN_EXE_sipr")));
    assert_eq!(code, Some(1), "sipr uac");
    assert_eq!(ours, theirs, "sipr sent different branches than real sipp");
}

// ---- ontimeout= on a <send> and a <recvCmd> -------------------------------

/// An OPTIONS naming its step in `X-Step`, with `attrs` on the `<send>`.
fn step_options(step: &str, attrs: &str) -> String {
    format!(
        r"  <send{attrs}><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:ot@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 OPTIONS
    Max-Forwards: 70
    X-Step: {step}
    Content-Length: 0

  ]]></send>
"
    )
}

/// What a UAC run against a silent UDP sink did: its exit code, each
/// `X-Step` the sink got with its arrival after the first rounded to 0.2 s,
/// and the rest of the first `-trace_err` line naming a timeout, after
/// `Call-Id: <id>, `.
#[derive(Debug, PartialEq)]
struct TimedRun {
    code: Option<i32>,
    steps: Vec<String>,
    warning: Option<String>,
}

/// Run `bin` on `xml` (plus `extra`) against a silent UDP sink with
/// `-trace_err`, listening to the sink while it runs.
fn run_timed_uac(bin: &std::path::Path, xml: &str, extra: &[&str]) -> TimedRun {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("timed.xml");
    std::fs::write(&path, xml).expect("write uac");
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let target = sink.local_addr().expect("sink addr").to_string();
    let mut uac = Reaper(
        tool_command(bin)
            .current_dir(dir.path())
            .args(["-sf", path.to_str().expect("utf8")])
            .args(["-i", "127.0.0.1", "-m", "1", "-timeout", "10", "-trace_err"])
            .args(extra)
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    sink.set_read_timeout(Some(Duration::from_millis(2500)))
        .expect("timeout");
    let mut steps = Vec::new();
    let mut first = None;
    let mut buf = [0u8; 65_535];
    while let Ok(n) = sink.recv(&mut buf) {
        let at = *first.get_or_insert_with(Instant::now);
        let step = String::from_utf8_lossy(&buf[..n])
            .lines()
            .find_map(|l| l.strip_prefix("X-Step:"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let fifths = (at.elapsed().as_millis() + 100) / 200;
        steps.push(format!("{step} {}.{}", fifths / 5, fifths % 5 * 2));
    }
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(12));
    let warning = sipp_error_log(dir.path()).lines().find_map(|l| {
        l.split_once("Call-Id: ")
            .and_then(|(_, rest)| rest.split_once(", "))
            .map(|(_, rest)| rest.to_owned())
    });
    TimedRun {
        code,
        steps,
        warning,
    }
}

/// SIPp takes `ontimeout=` on any message (`getCommonAttributes`). On a
/// `<send>` it is where the call goes once the send's UDP retransmissions
/// run out: one retransmission interval after the last one, with SIPp's
/// warning, instead of the call failing. Messages: 0 the retransmitted
/// OPTIONS, 1 the 200 it never gets, 2 skipped, 3 `late`.
#[test]
fn a_sends_ontimeout_follows_exhausted_retransmissions_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::a_sends_ontimeout_follows_exhausted_retransmissions_like_real_sipp \
             — no sipp."
        );
        return;
    };
    let xml = format!(
        r#"<scenario name="send-ontimeout">
{first}  <recv response="200"/>
{skipped}  <label id="late"/>
{late}</scenario>
"#,
        first = step_options("first", r#" retrans="200" ontimeout="late""#),
        skipped = step_options("skipped", ""),
        late = step_options("late", ""),
    );
    let theirs = run_timed_uac(&sipp, &xml, &["-max_retrans", "2"]);
    assert_eq!(
        theirs,
        TimedRun {
            code: Some(0),
            steps: vec![
                "first 0.0".into(),
                "first 0.2".into(),
                "first 0.6".into(),
                "late 1.4".into()
            ],
            warning: Some("timeout on max UDP retrans for message 1, jumping to label 3 ".into()),
        },
        "real sipp"
    );
    let ours = run_timed_uac(
        &PathBuf::from(env!("CARGO_BIN_EXE_sipr")),
        &xml,
        &["-max_retrans", "2"],
    );
    assert_eq!(ours, theirs, "sipr differs from real sipp");
}

/// Accept the one twin link `listener` gets and hold it, reading until the
/// peer closes it or 10 s pass: a 3PCC twin that never answers.
fn silent_twin(listener: TcpListener) -> std::thread::JoinHandle<()> {
    use std::io::Read;
    std::thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking twin");
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break Some(stream),
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break None,
            }
        };
        let Some(mut stream) = stream else {
            return;
        };
        stream.set_nonblocking(false).expect("blocking twin");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("twin timeout");
        let mut buf = [0u8; 4096];
        while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
    })
}

/// A `<recvCmd>`'s `ontimeout=` is where `-recv_timeout` sends the call when
/// no command comes, as on a `<recv>`. Messages: 0 an OPTIONS, 1 the
/// `<sendCmd>` that dials the (silent) twin, 2 the `<recvCmd>`, 3 skipped,
/// 4 `late`.
#[test]
fn a_recv_cmds_ontimeout_takes_the_receive_timeout_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!(
            "SKIPPED interop::a_recv_cmds_ontimeout_takes_the_receive_timeout_like_real_sipp \
             — no sipp."
        );
        return;
    };
    let xml = format!(
        r#"<scenario name="cmd-ontimeout">
{first}  <sendCmd><![CDATA[
    Call-ID: [call_id]
    X-Offer: hello
  ]]></sendCmd>
  <recvCmd ontimeout="late"/>
{skipped}  <label id="late"/>
{late}</scenario>
"#,
        first = step_options("first", ""),
        skipped = step_options("skipped", ""),
        late = step_options("late", ""),
    );
    let run = |bin: &std::path::Path| {
        let twin = TcpListener::bind("127.0.0.1:0").expect("bind twin");
        let twin_addr = twin.local_addr().expect("twin addr").to_string();
        let held = silent_twin(twin);
        let run = run_timed_uac(bin, &xml, &["-3pcc", &twin_addr, "-recv_timeout", "600"]);
        held.join().expect("twin thread");
        run
    };
    let theirs = run(&sipp);
    assert_eq!(
        theirs,
        TimedRun {
            code: Some(0),
            steps: vec!["first 0.0".into(), "late 0.6".into()],
            warning: Some("receive timeout on message cmd-ontimeout:2, jumping to label 4".into()),
        },
        "real sipp"
    );
    let ours = run(&PathBuf::from(env!("CARGO_BIN_EXE_sipr")));
    assert_eq!(ours, theirs, "sipr differs from real sipp");
}

// ---- a variable's number: SIPp's getDouble() and toDouble() ---------------

/// A UAC reading variables as numbers every way SIPp does. `getDouble` is
/// 0 for anything but a double: an `<add>` on the string "5" gives 1, an
/// `<assign variable=>` from a string or a bool gives 0 (rendered empty),
/// and a `<test>` of the string "5" against 5 is false, so the `condexec`
/// send is skipped. `<todouble>` parses a whole string (leading blanks
/// allowed, "" is 0) and leaves its target alone, with a warning, when it
/// cannot. The two `<test>` results render as `true` and `false`.
const NUMBERS_UAC_XML: &str = r#"<scenario name="numbers">
  <nop>
    <action>
      <assignstr assign_to="t" value="5"/>
      <add assign_to="t" value="1"/>
      <assignstr assign_to="s5" value="5"/>
      <assign assign_to="fromstr" variable="s5"/>
      <assign assign_to="seven" value="7"/>
      <test assign_to="b" variable="seven" compare="equal" value="7"/>
      <assign assign_to="frombool" variable="b"/>
      <assignstr assign_to="s" value=" 12.5"/>
      <todouble assign_to="d" variable="s"/>
      <assignstr assign_to="bad" value="12abc"/>
      <assign assign_to="kept" value="3"/>
      <todouble assign_to="kept" variable="bad"/>
      <assignstr assign_to="empty" value=""/>
      <assign assign_to="e" value="3"/>
      <todouble assign_to="e" variable="empty"/>
      <test assign_to="cmp" variable="s5" compare="equal" value="5"/>
    </action>
  </nop>
  <send><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:num@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 OPTIONS
    Max-Forwards: 70
    X-Values: [$t]|[$fromstr]|[$frombool]|[$d]|[$kept]|[$e]|[$b]|[$cmp]
    Content-Length: 0

  ]]></send>
  <send condexec="cmp"><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:num@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 2 OPTIONS
    Max-Forwards: 70
    X-Values: compared-equal
    Content-Length: 0

  ]]></send>
</scenario>
"#;

/// Run `uac_bin` on [`NUMBERS_UAC_XML`] against a UDP sink with
/// `-trace_err`. Returns the exit code, every `X-Values` the sink got, and
/// whether the error log has the failed `<todouble>`'s warning (SIPp names
/// the variables by internal ids, sipr by name, so only its start counts).
fn run_numbers_uac(uac_bin: &std::path::Path) -> (Option<i32>, Vec<String>, bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let xml = dir.path().join("numbers.xml");
    std::fs::write(&xml, NUMBERS_UAC_XML).expect("write uac");
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let target = sink.local_addr().expect("sink addr").to_string();
    let mut uac = Reaper(
        tool_command(uac_bin)
            .current_dir(dir.path())
            .args(["-sf", xml.to_str().expect("utf8")])
            .args(["-i", "127.0.0.1", "-m", "1", "-timeout", "20", "-trace_err"])
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    sink.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut values = Vec::new();
    let mut buf = [0u8; 65_535];
    while let Ok(n) = sink.recv(&mut buf) {
        if let Some(v) = String::from_utf8_lossy(&buf[..n])
            .lines()
            .find_map(|l| l.strip_prefix("X-Values:"))
        {
            values.push(v.trim().to_owned());
        }
    }
    let warned = sipp_error_log(dir.path()).contains("Invalid double conversion from $");
    (code, values, warned)
}

/// Variables read as numbers the way SIPp reads them (docs/SIPP_COMPAT.md
/// §6): `getDouble` everywhere, `toDouble` in `<todouble>` only. Bools
/// render as SIPp's `E_Message_Variable` writes them, a false one as
/// `false`.
#[test]
fn variables_read_and_render_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::variables_read_and_render_like_real_sipp — no sipp.");
        return;
    };
    let theirs = run_numbers_uac(&sipp);
    assert_eq!(
        theirs,
        (
            Some(0),
            vec!["1.000000|||12.500000|3.000000||true|false".to_owned()],
            true
        ),
        "real sipp"
    );
    let ours = run_numbers_uac(&PathBuf::from(env!("CARGO_BIN_EXE_sipr")));
    assert_eq!(
        ours, theirs,
        "sipr read or rendered differently than real sipp"
    );
}

// ---- +N/-N keyword offsets --------------------------------------------------

/// A UAC rendering SIPp's keyword offsets: kept on `[cseq]`, the ports and
/// `[len]` (`%5u`, 0 with no body), dropped on `[call_number]`.
const OFFSETS_UAC_XML: &str = r#"<scenario name="offsets">
  <send><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:o@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: [cseq] OPTIONS
    X-Off: [cseq+1]|[cseq-1]|[remote_port+1]|[local_port-1]|[call_number+1]
    Content-Type: application/sdp
    Content-Length: [len+3]

    v=0
    o=- 1 1 IN IP4 [local_ip]

  ]]></send>
  <send><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:o@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: [cseq] OPTIONS
    Content-Length: [len]

  ]]></send>
</scenario>
"#;

/// Run `uac_bin` on [`OFFSETS_UAC_XML`] from local `port` to `sink`.
/// Returns its exit code and the `X-Off` and `Content-Length` lines the
/// sink got.
fn run_offsets_uac(
    uac_bin: &std::path::Path,
    sink: &UdpSocket,
    port: u16,
) -> (Option<i32>, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let xml = dir.path().join("offsets.xml");
    std::fs::write(&xml, OFFSETS_UAC_XML).expect("write uac");
    let target = sink.local_addr().expect("sink addr").to_string();
    let mut uac = Reaper(
        tool_command(uac_bin)
            .current_dir(dir.path())
            .args(["-sf", xml.to_str().expect("utf8")])
            .args(["-i", "127.0.0.1", "-p", &port.to_string()])
            .args(["-m", "1", "-timeout", "20"])
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    sink.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut lines = Vec::new();
    let mut buf = [0u8; 65_535];
    while let Ok(n) = sink.recv(&mut buf) {
        lines.extend(
            String::from_utf8_lossy(&buf[..n])
                .split("\r\n")
                .filter(|l| l.starts_with("X-Off:") || l.starts_with("Content-Length:"))
                .map(ToOwned::to_owned),
        );
    }
    (code, lines)
}

/// SIPp's `+N`/`-N` keyword offsets (docs/SIPP_COMPAT.md §2): the same
/// UAC, same local port and same sink, sends the same header values under
/// sipr and real sipp.
#[test]
fn keyword_offsets_render_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::keyword_offsets_render_like_real_sipp — no sipp.");
        return;
    };
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let sink_port = sink.local_addr().expect("sink addr").port();
    let port = free_port();
    let theirs = run_offsets_uac(&sipp, &sink, port);
    assert_eq!(
        theirs,
        (
            Some(0),
            vec![
                format!("X-Off: 2|0|{}|{}|1", sink_port + 1, port - 1),
                "Content-Length:    34".to_owned(),
                "Content-Length:     0".to_owned(),
            ]
        ),
        "real sipp"
    );
    let ours = run_offsets_uac(&PathBuf::from(env!("CARGO_BIN_EXE_sipr")), &sink, port);
    assert_eq!(ours, theirs, "sipr rendered differently than real sipp");
}

// ---- a <pause>'s and a <timewait>'s actions --------------------------------

/// A UAC whose pause runs actions when it starts: a `<log>` (before the
/// `<assignstr>` after it), an `<assignstr>`, and a `<jump>` to message 3
/// that takes effect once the pause is over. Its closing timewait logs.
/// Messages: 0 the pause, 1-2 skipped, 3 `landed`, 4 the timewait.
fn pause_actions_uac_xml() -> String {
    format!(
        r#"<scenario name="pause-actions">
  <pause milliseconds="300"><action><log message="paused [$x]"/><assignstr assign_to="x" value="set"/><jump value="3"/></action></pause>
{s1}{s2}{landed}  <timewait milliseconds="100"><action><log message="timewait [$x]"/></action></timewait>
</scenario>
"#,
        s1 = step_options("skipped-1 [$x]", ""),
        s2 = step_options("skipped-2 [$x]", ""),
        landed = step_options("landed [$x]", ""),
    )
}

/// Run `uac_bin` on [`pause_actions_uac_xml`] against a UDP sink with
/// `-trace_logs` and `-trace_counts`. Returns the exit code, the
/// `X-Step`s the sink got, the log lines, and the last counts row without
/// its two time columns.
fn run_pause_actions_uac(
    uac_bin: &std::path::Path,
) -> (Option<i32>, Vec<String>, Vec<String>, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let xml = dir.path().join("pause_actions.xml");
    std::fs::write(&xml, pause_actions_uac_xml()).expect("write uac");
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let target = sink.local_addr().expect("sink addr").to_string();
    let mut uac = Reaper(
        tool_command(uac_bin)
            .current_dir(dir.path())
            .args(["-sf", xml.to_str().expect("utf8")])
            .args(["-i", "127.0.0.1", "-m", "1", "-timeout", "20"])
            .args(["-trace_logs", "-trace_counts"])
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    sink.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut steps = Vec::new();
    let mut buf = [0u8; 65_535];
    while let Ok(n) = sink.recv(&mut buf) {
        if let Some(step) = String::from_utf8_lossy(&buf[..n])
            .lines()
            .find_map(|l| l.strip_prefix("X-Step:"))
        {
            steps.push(step.trim().to_owned());
        }
    }
    let read = |suffix: &str| {
        std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .find(|e| e.file_name().to_string_lossy().ends_with(suffix))
            .map(|e| std::fs::read_to_string(e.path()).expect("read"))
            .unwrap_or_default()
    };
    let logs = read("_logs.log").lines().map(ToOwned::to_owned).collect();
    let counts = read("_counts.csv")
        .lines()
        .last()
        .and_then(|row| row.splitn(3, ';').nth(2))
        .unwrap_or_default()
        .to_owned();
    (code, steps, logs, counts)
}

/// SIPp reads `<action>` on every message (`getCommonAttributes`) and runs
/// a pause's, and a timewait's, when it starts (docs/SIPP_COMPAT.md §6): a
/// `<jump>` there lands once the pause is over. A timewait counts a Pause
/// session as a pause does.
#[test]
fn a_pauses_actions_run_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::a_pauses_actions_run_like_real_sipp — no sipp.");
        return;
    };
    let theirs = run_pause_actions_uac(&sipp);
    assert_eq!(
        theirs,
        (
            Some(0),
            vec!["landed set".to_owned()],
            vec!["paused ".to_owned(), "timewait set".to_owned()],
            "1;0;0;0;0;0;1;0;1;0;".to_owned()
        ),
        "real sipp"
    );
    let ours = run_pause_actions_uac(&PathBuf::from(env!("CARGO_BIN_EXE_sipr")));
    assert_eq!(
        ours, theirs,
        "sipr ran the pause differently than real sipp"
    );
}

// ---- twin commands in -trace_msg and -trace_shortmsg ----------------------

/// Accept the one twin link `listener` gets, answer its first command with
/// `Call-ID: <its call>` and `X-Answer: back`, and hold the link until the
/// peer closes it or 10 s pass.
fn answering_twin(listener: TcpListener) -> std::thread::JoinHandle<()> {
    use std::io::{Read, Write};
    std::thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking twin");
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break Some(stream),
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break None,
            }
        };
        let Some(mut stream) = stream else {
            return;
        };
        stream.set_nonblocking(false).expect("blocking twin");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("twin timeout");
        let mut command = Vec::new();
        let mut byte = [0u8; 1];
        while let Ok(1) = stream.read(&mut byte) {
            if byte[0] == 0x1b {
                break;
            }
            command.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&command).into_owned();
        if let Some(call_id) = text.lines().find_map(|l| l.strip_prefix("Call-ID:")) {
            let reply = format!("Call-ID: {}\r\nX-Answer: back\u{1b}", call_id.trim());
            let _ = stream.write_all(reply.as_bytes());
        }
        let mut buf = [0u8; 4096];
        while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
    })
}

/// What a 3PCC controller traced of its twin link: its exit code, each
/// `-trace_msg` control frame as `<direction> [text±<n>] <text>` (the byte
/// count against the length of the text printed), each `-trace_shortmsg`
/// line of a command without its timestamp, and the `Unexpected control
/// message` lines. The call's Call-ID reads `CID`.
#[derive(Debug, PartialEq)]
struct TwinTrace {
    code: Option<i32>,
    frames: Vec<String>,
    short: Vec<String>,
    unexpected: Vec<String>,
}

/// Run `bin` on `xml` as a 3PCC controller with `-trace_msg` and
/// `-trace_shortmsg`, against an answering twin and a silent UDP sink.
fn run_twin_trace(bin: &std::path::Path, xml: &str) -> TwinTrace {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("twin_trace.xml");
    std::fs::write(&path, xml).expect("write controller");
    let twin = TcpListener::bind("127.0.0.1:0").expect("bind twin");
    let twin_addr = twin.local_addr().expect("twin addr").to_string();
    let held = answering_twin(twin);
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let target = sink.local_addr().expect("sink addr").to_string();
    let mut controller = Reaper(
        tool_command(bin)
            .current_dir(dir.path())
            .args(["-sf", path.to_str().expect("utf8"), "-3pcc", &twin_addr])
            .args(["-i", "127.0.0.1", "-m", "1", "-timeout", "10"])
            .args(["-trace_msg", "-trace_shortmsg"])
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn controller"),
    );
    let code = wait_with_timeout(&mut controller.0, Duration::from_secs(12));
    held.join().expect("twin thread");
    let read = |suffix: &str| {
        std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .find(|e| e.file_name().to_string_lossy().ends_with(suffix))
            .map(|e| std::fs::read_to_string(e.path()).expect("read trace"))
            .unwrap_or_default()
    };
    // SIPp also writes two lines of debris about the twin socket closing
    // ("Problem EAGAIN on socket …", "Exit problem event on socket …").
    let messages: String = read("_messages.log")
        .split_inclusive('\n')
        .filter(|l| !l.starts_with("Problem EAGAIN") && !l.starts_with("Exit problem event"))
        .collect();
    let call_id = messages
        .lines()
        .find_map(|l| l.strip_prefix("Call-ID: "))
        .map(|v| v.trim_end_matches('\r').to_owned())
        .unwrap_or_default();
    let mask = |text: &str| {
        if call_id.is_empty() {
            text.to_owned()
        } else {
            text.replace(&call_id, "CID")
        }
    };
    let frames = messages
        .split("----------------------------------------------- ")
        .filter_map(|frame| {
            let (_, rest) = frame.split_once('\n')?;
            let (head, text) = rest.split_once(" bytes:\n\n")?;
            let (what, bytes) = head.rsplit_once(" [")?;
            let direction = what.strip_prefix("TCP control message ")?;
            let bytes: i64 = bytes.trim_end_matches(']').parse().ok()?;
            let text = text.strip_suffix('\n').unwrap_or(text);
            let text = text.split("\nUnexpected control message").next()?;
            let extra = bytes - i64::try_from(text.len()).ok()?;
            Some(format!("{direction} [text{extra:+}] {}", mask(text)))
        })
        .collect();
    let short = read("_shortmessages.log")
        .lines()
        .filter(|l| l.contains("\tCall-ID:"))
        .map(|l| {
            let fields: Vec<&str> = l.split('\t').collect();
            mask(&fields[3..].join("\t"))
        })
        .collect();
    let unexpected = messages
        .split("Unexpected control message")
        .skip(1)
        .map(|rest| {
            let entry = rest
                .split("-----------------------------------------------")
                .next();
            mask(&format!(
                "Unexpected control message{}",
                entry.unwrap_or_default()
            ))
        })
        .collect();
    TwinTrace {
        code,
        frames,
        short,
        unexpected,
    }
}

/// SIPp's socket layer traces the twin link like any other, tagged
/// `control` (docs/SIPP_COMPAT.md §6): a sent command with its ESC, a
/// received one without it but counted, `S` and `R` short lines with an
/// empty CSeq, and a command the call did not expect as an `Unexpected
/// control message` entry.
#[test]
fn twin_commands_are_traced_like_real_sipps() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::twin_commands_are_traced_like_real_sipps — no sipp.");
        return;
    };
    let sipr = PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let controller = |tail: &str| {
        format!(
            r#"<scenario name="twin-trace">
{first}  <sendCmd><![CDATA[
    Call-ID: [call_id]
    X-Offer: hello
  ]]></sendCmd>
{tail}</scenario>
"#,
            first = step_options("first", ""),
        )
    };
    let expected = controller("  <recvCmd/>\n");
    let theirs = run_twin_trace(&sipp, &expected);
    assert_eq!(
        theirs,
        TwinTrace {
            code: Some(0),
            frames: vec![
                "sent [text+0] Call-ID: CID\r\nX-Offer: hello\r\n\r\n\u{1b}".into(),
                "received [text+1] Call-ID: CID\r\nX-Answer: back".into(),
            ],
            short: vec![
                "S\tCID\tCSeq:\tCall-ID: CID".into(),
                "R\tCID\tCSeq:\tCall-ID: CID".into(),
            ],
            unexpected: vec![],
        },
        "real sipp"
    );
    assert_eq!(run_twin_trace(&sipr, &expected), theirs, "sipr, expected");

    // The call waits for a SIP 200 when the command arrives.
    let unexpected = controller("  <recv response=\"200\"/>\n");
    let theirs = run_twin_trace(&sipp, &unexpected);
    assert_eq!(theirs.code, Some(1), "real sipp: the call is rejected");
    assert_eq!(
        theirs.unexpected,
        [
            "Unexpected control message received (I was expecting a different type of \
          message):\nCall-ID: CID\r\nX-Answer: back\n"
        ],
        "real sipp"
    );
    assert_eq!(
        run_twin_trace(&sipr, &unexpected),
        theirs,
        "sipr, unexpected"
    );
}

// ---- <assign>: SIPp's value= and variable= forms --------------------------

/// A UAC whose nop assigns doubles both ways SIPp's `handle_rhs` allows and
/// sends them in an OPTIONS: `value=` (the documented form) positive and
/// negative, then `variable=` from a double, which an `<add>` shows is a
/// double too.
const ASSIGN_UAC_XML: &str = r#"<scenario name="assign-forms">
  <nop>
    <action>
      <assign assign_to="seven" value="7"/>
      <assign assign_to="neg" value="-2.5"/>
      <assign assign_to="copy" variable="seven"/>
      <add assign_to="copy" value="1"/>
    </action>
  </nop>
  <send><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:assign@[local_ip]:[local_port]>;tag=[call_number]
    To: <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 OPTIONS
    Max-Forwards: 70
    X-Assigned: [$seven]|[$neg]|[$copy]
    Content-Length: 0

  ]]></send>
</scenario>
"#;

/// Run `uac_bin` on [`ASSIGN_UAC_XML`] against a UDP sink. Returns its exit
/// code and the `X-Assigned` value of the first OPTIONS the sink got.
fn run_assign_uac(uac_bin: &std::path::Path) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let xml = dir.path().join("assign_forms.xml");
    std::fs::write(&xml, ASSIGN_UAC_XML).expect("write uac");
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let target = sink.local_addr().expect("sink addr").to_string();
    let mut uac = Reaper(
        tool_command(uac_bin)
            .current_dir(dir.path())
            .args(["-sf", xml.to_str().expect("utf8")])
            .args(["-i", "127.0.0.1", "-m", "1", "-timeout", "20"])
            .arg(&target)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    sink.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut buf = [0u8; 65_535];
    let assigned = sink.recv(&mut buf).map_or_else(
        |_| "<nothing sent>".to_owned(),
        |n| {
            String::from_utf8_lossy(&buf[..n])
                .lines()
                .find_map(|l| l.strip_prefix("X-Assigned:"))
                .unwrap_or("<no X-Assigned>")
                .trim()
                .to_owned()
        },
    );
    (code, assigned)
}

/// `<assign value=>`, the form SIPp documents, and `<assign variable=>`
/// both store a double, under sipr as under real sipp.
#[test]
fn assign_takes_a_value_or_a_variable_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::assign_takes_a_value_or_a_variable_like_real_sipp — no sipp.");
        return;
    };
    let (code, theirs) = run_assign_uac(&sipp);
    assert_eq!(code, Some(0), "real sipp uac");
    assert_eq!(theirs, "7.000000|-2.500000|8.000000", "real sipp");
    let (code, ours) = run_assign_uac(&PathBuf::from(env!("CARGO_BIN_EXE_sipr")));
    assert_eq!(code, Some(0), "sipr uac");
    assert_eq!(ours, theirs, "sipr assigned differently than real sipp");
}

// ---- recv timeouts: the recv the call waits at owns the timeout ----------

/// A UAS that answers the INVITE, takes the ACK, then waits in a recv
/// window whose timeout jumps are told apart by the `X-Branch` of the BYE
/// each label sends. Messages: 0 INVITE, 1 200, 2 ACK, 3 INFO (optional),
/// then the tail's.
fn recv_timeout_uas_xml(tail: &str) -> String {
    format!(
        r#"<scenario name="recv-timeout-uas">
  <recv request="INVITE"/>
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
{tail}</scenario>
"#
    )
}

/// The BYE a timeout jump to `branch` sends back to the UAC.
fn branch_bye(branch: &str, attrs: &str) -> String {
    format!(
        r"  <send{attrs}><![CDATA[
    BYE sip:uac@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:svc@[local_ip]:[local_port]>;tag=[pid]SIPpTag01[call_number]
    To: <sip:uac@[remote_ip]:[remote_port]>;tag=rt-uac
    Call-ID: [call_id]
    CSeq: 1 BYE
    X-Branch: {branch}
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
"
    )
}

/// One call against a recv-timeout UAS: its exit code (`None`: still
/// running, reaped), the first request it sent back (`X-Branch`, delay
/// after the ACK to the nearest 500 ms) and its `-trace_err` log.
#[derive(Debug)]
struct RecvTimeoutOutcome {
    code: Option<i32>,
    request: Option<(String, u128)>,
    error_log: String,
}

/// Where `run_recv_timeout_uas` keeps the UAS's stderr, in its tempdir.
const UAS_STDERR: &str = "uas.stderr";

/// What a UAS that never answered left behind: whether it is still running
/// or how it exited, its stderr and its `-trace_err` log.
fn uas_post_mortem(uas: &mut Child, dir: &std::path::Path) -> String {
    let status = match uas.try_wait() {
        Ok(Some(status)) => status.to_string(),
        Ok(None) => "still running".to_owned(),
        Err(e) => format!("unknown ({e})"),
    };
    let stderr = std::fs::read_to_string(dir.join(UAS_STDERR)).unwrap_or_default();
    format!(
        "status: {status}\n--- stderr ---\n{stderr}\n--- -trace_err ---\n{}",
        sipp_error_log(dir)
    )
}

/// Run `uas_bin` on `xml` (plus `extra`) and place one call on it from a
/// raw UDP UAC: INVITE, ACK the 200, an INFO `info_after` the ACK if
/// given, then listen `listen` for a request back.
fn run_recv_timeout_uas(
    uas_bin: &std::path::Path,
    xml: &str,
    extra: &[&str],
    info_after: Option<Duration>,
    listen: Duration,
) -> RecvTimeoutOutcome {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("recv_timeout_uas.xml");
    std::fs::write(&path, xml).expect("write uas");
    let port = free_port();
    let stderr = std::fs::File::create(dir.path().join(UAS_STDERR)).expect("create uas stderr");
    let mut uas = Reaper(
        tool_command(uas_bin)
            .current_dir(dir.path())
            .args([
                "-sf",
                path.to_str().expect("utf8"),
                "-i",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "1",
                "-timeout",
                "6",
                "-trace_err",
            ])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(stderr)
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let uas_addr = format!("127.0.0.1:{port}");
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uac");
    let local = sock.local_addr().expect("uac addr");
    let request = |method: &str, cseq: u32, to_tag: &str| {
        format!(
            "{method} sip:svc@{uas_addr} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {local};branch=z9hG4bK-rt-{method}-{cseq}\r\n\
             From: <sip:uac@{local}>;tag=rt-uac\r\n\
             To: <sip:svc@{uas_addr}>{to_tag}\r\n\
             Call-ID: recv-timeout-{}@127.0.0.1\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:uac@{local}>\r\n\
             Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
            local.port()
        )
    };
    let header = |text: &str, name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_owned())
    };
    let mut buf = [0u8; 65_535];
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    let mut to_tag = None;
    for _ in 0..10 {
        sock.send_to(request("INVITE", 1, "").as_bytes(), &uas_addr)
            .expect("send invite");
        if let Ok(n) = sock.recv(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            if text.starts_with("SIP/2.0 200") {
                let to = header(&text, "To:").unwrap_or_default();
                to_tag = to.split_once(";tag=").map(|(_, t)| format!(";tag={t}"));
                break;
            }
        }
    }
    let Some(to_tag) = to_tag else {
        panic!(
            "{} on 127.0.0.1:{port} never answered the INVITE\n{}",
            uas_bin.display(),
            uas_post_mortem(&mut uas.0, dir.path()),
        );
    };
    sock.send_to(request("ACK", 1, &to_tag).as_bytes(), &uas_addr)
        .expect("send ack");
    let ack_at = Instant::now();
    if let Some(delay) = info_after {
        std::thread::sleep(delay);
        sock.send_to(request("INFO", 2, &to_tag).as_bytes(), &uas_addr)
            .expect("send info");
    }
    let mut back = None;
    while let Some(left) = listen.checked_sub(ack_at.elapsed()) {
        sock.set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .expect("timeout");
        let Ok(n) = sock.recv(&mut buf) else {
            break;
        };
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        if !text.starts_with("SIP/2.0") {
            let branch = header(&text, "X-Branch:").unwrap_or_default();
            back = Some((branch, (ack_at.elapsed().as_millis() + 250) / 500));
            break;
        }
    }
    let code = wait_with_timeout(&mut uas.0, Duration::from_secs(8));
    RecvTimeoutOutcome {
        code,
        request: back,
        error_log: sipp_error_log(dir.path()),
    }
}

/// The receive timeout at parity with real sipp (docs/SIPP_COMPAT.md §6):
/// the call waits at the first recv of its window, so that recv's own
/// `timeout=` (else `-recv_timeout`) runs and its `ontimeout` is the one
/// taken; an optional match moves the call on to the next recv, whose own
/// timeout starts afresh; a label past the last message fails the call.
/// Each case runs the same UAS under both tools against the same
/// scripted UAC.
#[test]
fn recv_timeouts_arm_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::recv_timeouts_arm_like_real_sipp — no sipp.");
        return;
    };
    let sipr = std::path::Path::new(env!("CARGO_BIN_EXE_sipr"));
    let trailing = recv_timeout_uas_xml(
        r#"  <recv request="INFO" optional="true" timeout="1000" ontimeout="end"/>
  <label id="end"/>
"#,
    );
    let window = recv_timeout_uas_xml(&format!(
        r#"  <recv request="INFO" optional="true" timeout="1500" ontimeout="early"/>
  <recv request="BYE" timeout="2500" ontimeout="late"/>
  <label id="early"/>
{early}  <label id="late"/>
{late}  <label id="done"/>
"#,
        early = branch_bye("early", r#" next="done""#),
        late = branch_bye("late", ""),
    ));
    let behind = recv_timeout_uas_xml(&format!(
        r#"  <recv request="INFO" optional="true"/>
  <recv request="BYE" timeout="1000" ontimeout="late"/>
  <label id="late"/>
{late}"#,
        late = branch_bye("late", ""),
    ));
    let listen = Duration::from_millis(4300);
    let info = Some(Duration::from_millis(1000));
    let cases: [(&str, &str, &[&str], Option<Duration>); 5] = [
        ("trailing optional", &trailing, &[], None),
        ("window", &window, &[], None),
        ("window, INFO at 1 s", &window, &[], info),
        ("timeout behind an optional", &behind, &[], None),
        (
            "-recv_timeout, behind an optional",
            &behind,
            &["-recv_timeout", "800"],
            None,
        ),
    ];
    let jump = |log: &str| {
        log.lines()
            .find_map(|l| l.split_once(", receive timeout on message "))
            .map(|(_, rest)| rest.to_owned())
    };
    // Every run on its own port and directory, all at once: the cases are
    // mostly waiting.
    let outcomes = std::thread::scope(|scope| {
        let runs: Vec<_> = cases
            .iter()
            .map(|&(_, xml, extra, info_after)| {
                let sipp = &sipp;
                (
                    scope.spawn(move || run_recv_timeout_uas(sipp, xml, extra, info_after, listen)),
                    scope.spawn(move || run_recv_timeout_uas(sipr, xml, extra, info_after, listen)),
                )
            })
            .collect();
        runs.into_iter()
            .map(|(theirs, ours)| {
                (
                    theirs.join().expect("sipp run"),
                    ours.join().expect("sipr run"),
                )
            })
            .collect::<Vec<_>>()
    });
    for ((name, ..), (theirs, ours)) in cases.iter().zip(outcomes) {
        let name = *name;
        assert_eq!(
            ours.code, theirs.code,
            "{name}: exit code\n{theirs:?}\n{ours:?}"
        );
        assert_eq!(ours.request, theirs.request, "{name}: timeout jump");
        assert_eq!(
            jump(&ours.error_log),
            jump(&theirs.error_log),
            "{name}: the timeout warning\n{}\n{}",
            theirs.error_log,
            ours.error_log
        );
        // Pin what real sipp does, so the comparison cannot pass vacuously.
        let (code, request, warning): (Option<i32>, Option<(&str, u128)>, Option<&str>) = match name
        {
            "trailing optional" => (
                Some(1),
                None,
                Some("recv-timeout-uas:3, jumping to label 4"),
            ),
            "timeout behind an optional" => (Some(1), None, None),
            "-recv_timeout, behind an optional" => (
                Some(1),
                None,
                Some(
                    "recv-timeout-uas:3 without label to jump to (ontimeout attribute): \
                         aborting call",
                ),
            ),
            "window, INFO at 1 s" => (
                Some(0),
                Some(("late", 7)),
                Some("recv-timeout-uas:4, jumping to label 6"),
            ),
            _ => (
                Some(0),
                Some(("early", 3)),
                Some("recv-timeout-uas:3, jumping to label 5"),
            ),
        };
        assert_eq!(theirs.code, code, "{name}: real sipp's exit code");
        assert_eq!(
            theirs.request.as_ref().map(|(b, t)| (b.as_str(), *t)),
            request,
            "{name}: real sipp's timeout jump"
        );
        assert_eq!(jump(&theirs.error_log).as_deref(), warning, "{name}");
    }
}

// ---- a matched recv follows its next=, test= and chance= -----------------

/// A UAS tail: `recvs` (an INFO recv, maybe behind others), a mandatory
/// UPDATE recv the UAC never sends (SIPp refuses an optional recv right
/// before a send), then three BYEs, told apart by `X-Branch`:
/// `fell-through` (the UPDATE recv, reached, timed out after 500 ms),
/// `jumped` (label `jumped`) and `timedout` (label `timedout`).
fn branching_recv_tail(recvs: &str) -> String {
    format!(
        r#"{recvs}
  <recv request="UPDATE" timeout="500" ontimeout="fell"/>
  <label id="fell"/>
{fell}  <label id="jumped"/>
{jumped}  <label id="timedout"/>
{timedout}  <label id="done"/>
"#,
        fell = branch_bye("fell-through", r#" next="done""#),
        jumped = branch_bye("jumped", r#" next="done""#),
        timedout = branch_bye("timedout", ""),
    )
}

/// Branching on a matched recv at parity with real sipp (docs/SIPP_COMPAT.md
/// §6, `call.cpp` ~l.5653 `process_incoming` and ~l.1920 `next()`): the
/// recv's `next=` is followed when its `test=` variable (if any) is set and
/// its `chance=` draw (if any) is won, else the call moves to the message
/// after it — except that an optional recv whose `test=` variable is unset
/// leaves the call at the recv it waited at, with that recv's receive
/// timeout still running from where it started. The same cases as e2e's
/// `a_matched_recv_follows_next_test_and_chance`, each run under both tools
/// against the same scripted UAC, which sends an INFO 1 s after the ACK.
#[test]
fn a_matched_recv_branches_like_real_sipp() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::a_matched_recv_branches_like_real_sipp — no sipp.");
        return;
    };
    let sipr = std::path::Path::new(env!("CARGO_BIN_EXE_sipr"));
    let unset = r#"<action><ereg regexp="X-Nope" search_in="msg" assign_to="flag"/></action>"#;
    let set = r#"<action><ereg regexp="INFO" search_in="msg" assign_to="flag"/></action>"#;
    let info = |attrs: &str, body: &str| {
        format!(
            r#"  <recv request="INFO"{attrs} timeout="2000" ontimeout="timedout">{body}</recv>"#
        )
    };
    let behind = format!(
        r#"  <recv request="OPTIONS" optional="true" timeout="2000" ontimeout="timedout"/>
  <recv request="INFO" optional="true" next="jumped" test="flag">{unset}</recv>"#
    );
    // Name, recvs, and what real sipp does: the BYE's `X-Branch`, when it
    // came (in 500 ms units after the ACK), and the timeout warning.
    let cases: [(&str, String, &str, u128, Option<&str>); 7] = [
        (
            "a mandatory recv follows next=",
            info(r#" next="jumped" counter="infos""#, ""),
            "jumped",
            2,
            None,
        ),
        (
            "a mandatory recv moves on when test= is unset",
            info(r#" next="jumped" test="flag""#, unset),
            "fell-through",
            3,
            Some("recv-timeout-uas:4, jumping to label 5"),
        ),
        (
            "an optional recv follows next= when test= is set",
            info(r#" optional="true" next="jumped" test="flag""#, set),
            "jumped",
            2,
            None,
        ),
        (
            "an optional recv stays when test= is unset",
            info(r#" optional="true" next="jumped" test="flag""#, unset),
            "timedout",
            4,
            Some("recv-timeout-uas:3, jumping to label 7"),
        ),
        (
            "the stay keeps the call at the recv it waited at",
            behind,
            "timedout",
            4,
            Some("recv-timeout-uas:3, jumping to label 8"),
        ),
        (
            "an optional recv without test= follows next=",
            info(r#" optional="true" next="jumped" chance="1""#, ""),
            "jumped",
            2,
            None,
        ),
        (
            "chance=0 never jumps",
            info(r#" optional="true" next="jumped" chance="0""#, ""),
            "fell-through",
            3,
            Some("recv-timeout-uas:4, jumping to label 5"),
        ),
    ];
    let jump = |log: &str| {
        log.lines()
            .find_map(|l| l.split_once(", receive timeout on message "))
            .map(|(_, rest)| rest.to_owned())
    };
    let listen = Duration::from_millis(3500);
    let info_after = Some(Duration::from_millis(1000));
    // Every run on its own port and directory, all at once: the cases are
    // mostly waiting.
    let outcomes = std::thread::scope(|scope| {
        let runs: Vec<_> = cases
            .iter()
            .map(|(_, recvs, ..)| {
                let xml = recv_timeout_uas_xml(&branching_recv_tail(recvs));
                let sipp = &sipp;
                let theirs = {
                    let xml = xml.clone();
                    scope.spawn(move || run_recv_timeout_uas(sipp, &xml, &[], info_after, listen))
                };
                let ours =
                    scope.spawn(move || run_recv_timeout_uas(sipr, &xml, &[], info_after, listen));
                (theirs, ours)
            })
            .collect();
        runs.into_iter()
            .map(|(theirs, ours)| {
                (
                    theirs.join().expect("sipp run"),
                    ours.join().expect("sipr run"),
                )
            })
            .collect::<Vec<_>>()
    });
    for ((name, _, branch, at, warning), (theirs, ours)) in cases.iter().zip(outcomes) {
        // Pin what real sipp does, so the comparison cannot pass vacuously.
        assert_eq!(theirs.code, Some(0), "{name}: real sipp's exit code");
        assert_eq!(
            theirs.request.as_ref().map(|(b, t)| (b.as_str(), *t)),
            Some((*branch, *at)),
            "{name}: real sipp's BYE"
        );
        assert_eq!(
            jump(&theirs.error_log).as_deref(),
            *warning,
            "{name}: real sipp's timeout warning"
        );
        assert_eq!(
            ours.code, theirs.code,
            "{name}: exit code\n{theirs:?}\n{ours:?}"
        );
        assert_eq!(ours.request, theirs.request, "{name}: the BYE sent");
        assert_eq!(
            jump(&ours.error_log),
            jump(&theirs.error_log),
            "{name}: the timeout warning\n{}\n{}",
            theirs.error_log,
            ours.error_log
        );
    }
}

// ---- generic counters (`counter=`) -------------------------------------

/// A UAC whose steps name counters (mirrored in `tests/e2e.rs`), in
/// first-mention order: `invites` (the INVITE), `1234567` (the 180, a
/// numeric name longer than SIPp's column buffer), `7` (the 200 and the
/// pause, shared), `acks`, `jumper` (a nop whose `<jump>` skips the next
/// message) and `skipped` (that message, which never runs). Per call:
/// 1, 1, 2, 1, 1, 0.
fn counters_uac_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="counters">
  <send retrans="500" counter="invites"><![CDATA[
      INVITE sip:svc@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:uac@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:svc@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 INVITE
      Contact: <sip:uac@[local_ip]:[local_port]>
      Max-Forwards: 70
      Content-Length: 0

    ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true" counter="1234567"/>
  <recv response="200" counter="7"/>
  <send counter="acks"><![CDATA[
      ACK sip:svc@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:uac@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 1 ACK
      Contact: <sip:uac@[local_ip]:[local_port]>
      Max-Forwards: 70
      Content-Length: 0

    ]]></send>
  <nop counter="jumper">
    <action><jump value="7"/></action>
  </nop>
  <nop counter="skipped"/>
  <pause milliseconds="50" counter="7"/>
  <send retrans="500"><![CDATA[
      BYE sip:svc@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:uac@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
      To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 2 BYE
      Contact: <sip:uac@[local_ip]:[local_port]>
      Max-Forwards: 70
      Content-Length: 0

    ]]></send>
  <recv response="200"/>
</scenario>
"#
}

/// Run `counters_uac_xml()` for 3 calls on `uac_bin` with `-trace_stat`
/// and `-trace_screen` against `uas_bin -sn uas`, in a fresh directory;
/// return the directory and the UAC's exit code.
fn run_counters_uac(
    uas_bin: &std::path::Path,
    uac_bin: &std::path::Path,
    tag: &str,
) -> (std::path::PathBuf, Option<i32>) {
    let dir = std::env::temp_dir().join(format!(
        "sipr-interop-counters-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let scenario = dir.join("counters.xml");
    std::fs::write(&scenario, counters_uac_xml()).expect("write scenario");
    let port = free_port();
    let mut uas = Reaper(
        tool_command(uas_bin)
            .current_dir(&dir)
            .args(["-sn", "uas", "-i", "127.0.0.1", "-p", &port.to_string()])
            .args(["-m", "3", "-timeout", "30"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uas"),
    );
    std::thread::sleep(Duration::from_millis(400));
    let mut uac = tool_command(uac_bin);
    uac.current_dir(&dir)
        .arg("-sf")
        .arg(&scenario)
        .args(["-i", "127.0.0.1", "-r", "10", "-m", "3", "-timeout", "20"])
        .args(["-trace_stat", "-trace_screen"]);
    // sipp's `-bg` forks and the parent exits at once (docs/TESTING.md):
    // real sipp runs in the foreground with its screen on a null stdout.
    if uac_bin == std::path::Path::new(env!("CARGO_BIN_EXE_sipr")) {
        uac.arg("-bg");
    }
    let mut uac = Reaper(
        uac.arg(format!("127.0.0.1:{port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn_outside_probes()
            .expect("spawn uac"),
    );
    let code = wait_with_timeout(&mut uac.0, Duration::from_secs(25));
    let _ = wait_with_timeout(&mut uas.0, Duration::from_secs(15));
    (dir, code)
}

/// The file in `dir` whose name ends with `suffix`.
fn read_file_ending(dir: &std::path::Path, suffix: &str) -> String {
    let name = std::fs::read_dir(dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.ends_with(suffix))
        .unwrap_or_else(|| panic!("no *{suffix} in {}", dir.display()));
    std::fs::read_to_string(dir.join(name)).expect("read")
}

/// The `(C)` values of the six counters in the last `-trace_stat` row,
/// found by their header names.
fn final_counter_values(stat: &str) -> Vec<String> {
    let header: Vec<&str> = stat.lines().next().expect("header").split(';').collect();
    let last: Vec<&str> = stat.lines().last().expect("row").split(';').collect();
    assert_eq!(last.len(), header.len(), "row width:\n{stat}");
    [
        "invites(C)",
        "GenericCounter12345(C)",
        "GenericCounter7(C)",
        "acks(C)",
        "jumper(C)",
        "skipped(C)",
    ]
    .iter()
    .map(|name| {
        let at = header
            .iter()
            .position(|c| c == name)
            .unwrap_or_else(|| panic!("no {name} column:\n{stat}"));
        last[at].to_owned()
    })
    .collect()
}

/// Generic counters at parity (SIPp `E_ADD_GENERIC_COUNTER`): sipr and real
/// sipp run the same UAC, and their `-trace_stat` headers are byte-for-byte
/// equal — the counters' `(P)`/`(C)` pairs after `CallLengthStDev`, in
/// first-mention order, `GenericCounter<n>` for a numeric name cut at 19
/// characters, a counter that never runs included. The final rows agree on
/// every counter, and a nop books its counter before its `<jump>` action.
/// Both statistics screens (`-trace_screen`) list a `Counter <name>` row.
#[test]
fn generic_counters_match_real_sipps_statistics() {
    let Some(sipp) = sipp_bin() else {
        eprintln!("SKIPPED interop::generic_counters_match_real_sipps_statistics — no sipp.");
        return;
    };
    let sipr = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sipr"));
    let (sipr_dir, sipr_code) = run_counters_uac(&sipp, &sipr, "sipr");
    let (sipp_dir, sipp_code) = run_counters_uac(&sipr, &sipp, "sipp");
    assert_eq!(sipp_code, Some(0), "real sipp's uac");
    assert_eq!(sipr_code, Some(0), "sipr's uac");
    let ours = read_file_ending(&sipr_dir, "_.csv");
    let theirs = read_file_ending(&sipp_dir, "_.csv");
    assert_eq!(
        ours.lines().next(),
        theirs.lines().next(),
        "-trace_stat header"
    );
    // Pin what real sipp counts, so the comparison cannot pass vacuously.
    let expected = ["3", "3", "6", "3", "3", "0"];
    assert_eq!(final_counter_values(&theirs), expected, "sipp:\n{theirs}");
    assert_eq!(final_counter_values(&ours), expected, "sipr:\n{ours}");
    for (dir, who) in [(&sipp_dir, "sipp"), (&sipr_dir, "sipr")] {
        // `<scenario>_<pid>_screen.log` on both sides: SIPp's `screen` log
        // file, whatever its help text says (`_screens.log`).
        let screens = read_file_ending(dir, "_screen.log");
        for name in ["invites", "1234567", "7", "acks", "jumper", "skipped"] {
            assert!(
                screens.contains(&format!("Counter {name} ")),
                "{who}: no Counter {name} row:\n{screens}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&sipr_dir);
    let _ = std::fs::remove_dir_all(&sipp_dir);
}
