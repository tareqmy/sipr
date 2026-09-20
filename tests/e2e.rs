//! End-to-end: the sipr binary places (and answers) real calls over loopback
//! against scripted peers implementing the classic uas flow (INVITE → 180 →
//! 200, ACK, BYE → 200), over UDP, TCP, and TLS. This is the always-on
//! complement to the real-SIPp interop suite in `tests/interop.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::time::Duration;

use sipr_net::{EscFramer, Inbound, TcpFramer};

/// Minimal scripted UAS. Answers until the socket is idle for `idle`.
fn spawn_uas(idle: Duration) -> (SocketAddr, std::thread::JoinHandle<UasStats>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(idle)).expect("timeout");
    let handle = std::thread::spawn(move || run_uas(&sock));
    (addr, handle)
}

#[derive(Default, Debug)]
struct UasStats {
    invites: u64,
    byes: u64,
    retrans_invites: u64,
}

fn run_uas(sock: &UdpSocket) -> UasStats {
    let mut stats = UasStats::default();
    let mut answered: HashMap<String, Vec<u8>> = HashMap::new(); // branch → 200
    let mut buf = [0u8; 65_535];
    while let Ok((n, from)) = sock.recv_from(&mut buf) {
        let Ok(msg) = Inbound::parse(&buf[..n]) else {
            continue;
        };
        match msg.method() {
            Some("INVITE") => {
                let branch = msg.top_via_branch().unwrap_or_default().to_owned();
                if let Some(ok) = answered.get(&branch) {
                    stats.retrans_invites += 1;
                    let _ = sock.send_to(ok, from); // retransmitted INVITE: resend 200
                    continue;
                }
                stats.invites += 1;
                let ringing = mirror_response(&msg, "180 Ringing", true);
                let ok = mirror_response(&msg, "200 OK", true);
                let _ = sock.send_to(&ringing, from);
                let _ = sock.send_to(&ok, from);
                answered.insert(branch, ok);
            }
            Some("ACK") => {}
            Some("BYE") => {
                stats.byes += 1;
                let ok = mirror_response(&msg, "200 OK", false);
                let _ = sock.send_to(&ok, from);
            }
            _ => {}
        }
    }
    stats
}

/// Build a response by mirroring Via/From/To/Call-ID/CSeq, adding a To tag
/// for dialog-establishing responses.
fn mirror_response(msg: &Inbound, status: &str, add_to_tag: bool) -> Vec<u8> {
    let mut out = format!("SIP/2.0 {status}\r\n");
    for via in msg.header_lines("Via") {
        out.push_str(via);
        out.push_str("\r\n");
    }
    for from in msg.header_lines("From") {
        out.push_str(from);
        out.push_str("\r\n");
    }
    let to = msg.header("To").unwrap_or_default();
    let has_tag = to.contains(";tag=");
    if add_to_tag && !has_tag {
        out.push_str(&format!("To: {to};tag=uas-e2e-1\r\n"));
    } else {
        out.push_str(&format!("To: {to}\r\n"));
    }
    out.push_str(&format!(
        "Call-ID: {}\r\n",
        msg.call_id().unwrap_or_default()
    ));
    out.push_str(&format!(
        "CSeq: {}\r\n",
        msg.header("CSeq").unwrap_or_default()
    ));
    out.push_str("Contact: <sip:uas@127.0.0.1>\r\nContent-Length: 0\r\n\r\n");
    out.into_bytes()
}

fn run_sipr(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sipr"))
        .args(args)
        .output()
        .expect("spawn sipr")
}

/// A UAS that answers only after a digest challenge, verifying the response.
/// It replies 401 to the first REGISTER (with a fixed nonce/realm) and, on
/// the authenticated retry, recomputes the expected digest and replies 200
/// only if it matches — so a green run proves sipr's `[authentication]` math.
fn spawn_digest_registrar(
    realm: &'static str,
    user: &'static str,
    pass: &'static str,
) -> (SocketAddr, std::thread::JoinHandle<bool>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind registrar");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let handle = std::thread::spawn(move || {
        let nonce = "deadbeefcafe";
        let mut buf = [0u8; 65_535];
        let mut authenticated = false;
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            if msg.method() != Some("REGISTER") {
                continue;
            }
            match msg.header("Authorization") {
                None => {
                    // Challenge.
                    let mut r = String::from("SIP/2.0 401 Unauthorized\r\n");
                    for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
                        for l in msg.header_lines(name) {
                            r.push_str(l);
                            r.push_str("\r\n");
                        }
                    }
                    r.push_str(&format!(
                        "WWW-Authenticate: Digest realm=\"{realm}\", nonce=\"{nonce}\", \
                         algorithm=MD5, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n"
                    ));
                    let _ = sock.send_to(r.as_bytes(), from);
                }
                Some(auth) => {
                    // Recompute the expected response from the header's own
                    // uri/cnonce/nc and compare.
                    let field = |k: &str| -> Option<String> {
                        auth.split(',').find_map(|p| {
                            let p = p.trim();
                            p.strip_prefix(&format!("{k}="))
                                .map(|v| v.trim_matches('"').to_owned())
                        })
                    };
                    let uri = field("uri").unwrap_or_default();
                    let cnonce = field("cnonce").unwrap_or_default();
                    let nc = field("nc").unwrap_or_default();
                    let ha1 = sipr_auth::md5_hex(format!("{user}:{realm}:{pass}").as_bytes());
                    let ha2 = sipr_auth::md5_hex(format!("REGISTER:{uri}").as_bytes());
                    let expected = sipr_auth::md5_hex(
                        format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes(),
                    );
                    let got = field("response").unwrap_or_default();
                    authenticated = got == expected;
                    let status = if authenticated {
                        "200 OK"
                    } else {
                        "403 Forbidden"
                    };
                    let mut r = format!("SIP/2.0 {status}\r\n");
                    for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
                        for l in msg.header_lines(name) {
                            r.push_str(l);
                            r.push_str("\r\n");
                        }
                    }
                    r.push_str("Content-Length: 0\r\n\r\n");
                    let _ = sock.send_to(r.as_bytes(), from);
                    if authenticated {
                        break;
                    }
                }
            }
        }
        authenticated
    });
    (addr, handle)
}

#[test]
fn embedded_uac_flow_completes_against_scripted_uas() {
    let (addr, uas) = spawn_uas(Duration::from_secs(3));
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-r",
        "10",
        "-m",
        "5",
        "-d",
        "50",
        "-timeout",
        "20",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected success; stderr:\n{err}"
    );
    assert!(
        err.contains("created 5 successful 5 failed 0"),
        "summary mismatch:\n{err}"
    );
    let uas_stats = uas.join().expect("uas thread");
    assert_eq!(uas_stats.invites, 5, "{uas_stats:?}");
    assert_eq!(uas_stats.byes, 5, "{uas_stats:?}");
}

#[test]
fn rate_and_limit_are_respected() {
    // -l 1 with a slow pause means calls serialize; -m 3 still completes.
    let (addr, _uas) = spawn_uas(Duration::from_secs(3));
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-r",
        "50",
        "-l",
        "1",
        "-m",
        "3",
        "-d",
        "30",
        "-timeout",
        "20",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 3 failed 0"), "{err}");
}

#[test]
fn silence_leads_to_failed_calls_and_exit_1() {
    // Nothing listens on this socket (we bind it and never read).
    let dead = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = dead.local_addr().expect("addr");
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-m",
        "1",
        "-nr",
        "-timeout",
        "1",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr:\n{err}");
    assert!(err.contains("failed 1"), "{err}");
}

/// A base port such that `base..base+span` are all free right now, for
/// scenarios that spread calls over `[auto_media_port]` blocks.
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

/// A free loopback UDP port (bind-then-drop).
fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("addr").port()
}

#[test]
fn sipr_uas_answers_sipr_uac_self_test() {
    let port = free_port();
    let uas = Command::new(env!("CARGO_BIN_EXE_sipr"))
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
            "20",
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn uas");
    std::thread::sleep(Duration::from_millis(300)); // let it bind
    let uac = run_sipr(&[
        "-sn",
        "uac",
        "-r",
        "20",
        "-m",
        "5",
        "-d",
        "50",
        "-timeout",
        "15",
        &format!("127.0.0.1:{port}"),
    ]);
    let uac_err = String::from_utf8_lossy(&uac.stderr);
    assert_eq!(uac.status.code(), Some(0), "uac stderr:\n{uac_err}");
    assert!(
        uac_err.contains("created 5 successful 5 failed 0"),
        "uac summary:\n{uac_err}"
    );
    let uas_out = uas.wait_with_output().expect("uas exit");
    let uas_err = String::from_utf8_lossy(&uas_out.stderr);
    assert_eq!(uas_out.status.code(), Some(0), "uas stderr:\n{uas_err}");
    assert!(
        uas_err.contains("created 5 successful 5 failed 0"),
        "uas summary:\n{uas_err}"
    );
}

#[test]
fn uas_auto_answers_in_dialog_options_with_aa() {
    let port = free_port();
    let uas = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .args([
            "-sn",
            "uas",
            "-i",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-aa",
            "-m",
            "1",
            "-timeout",
            "15",
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn uas");
    std::thread::sleep(Duration::from_millis(300));
    // UAC flow with an in-dialog OPTIONS the UAS scenario does not expect.
    let uac_scenario = r#"<scenario name="uac-with-options">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="180" optional="true"/>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <send retrans="500"><![CDATA[
    OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 OPTIONS
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 3 BYE
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let dir = std::env::temp_dir();
    let path = dir.join(format!("sipr-aa-{}.xml", std::process::id()));
    std::fs::write(&path, uac_scenario).expect("write scenario");
    let uac = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-m",
        "1",
        "-timeout",
        "10",
        &format!("127.0.0.1:{port}"),
    ]);
    let _ = std::fs::remove_file(&path);
    let uac_err = String::from_utf8_lossy(&uac.stderr);
    assert_eq!(uac.status.code(), Some(0), "uac stderr:\n{uac_err}");
    let uas_out = uas.wait_with_output().expect("uas exit");
    let uas_err = String::from_utf8_lossy(&uas_out.stderr);
    assert_eq!(uas_out.status.code(), Some(0), "uas stderr:\n{uas_err}");
}

#[test]
fn trace_files_are_written() {
    let (addr, _uas) = spawn_uas(Duration::from_secs(3));
    let dir = std::env::temp_dir().join(format!("sipr-traces-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let out = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .current_dir(&dir)
        .args([
            "-sn",
            "uac",
            "-m",
            "2",
            "-d",
            "30",
            "-timeout",
            "15",
            "-trace_msg",
            "-trace_err",
            "-trace_stat",
            &addr.to_string(),
        ])
        .output()
        .expect("run sipr");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let names: Vec<String> = std::fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let msg_log = names.iter().find(|n| n.ends_with("_messages.log"));
    let csv = names.iter().find(|n| n.ends_with("_.csv"));
    assert!(msg_log.is_some() && csv.is_some(), "files: {names:?}");
    let msg_content =
        std::fs::read_to_string(dir.join(msg_log.expect("msg log"))).expect("read log");
    assert!(
        msg_content.contains("INVITE sip:service@"),
        "message log content"
    );
    assert!(msg_content.contains("received from"), "inbound traced too");
    let csv_content = std::fs::read_to_string(dir.join(csv.expect("csv"))).expect("read csv");
    assert!(csv_content.starts_with("CurrentTime;"), "csv header");
    assert!(csv_content.lines().count() >= 2, "csv rows:\n{csv_content}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn retransmissions_fire_when_first_invite_is_lost() {
    // A UAS that ignores the first INVITE per branch: the call only
    // completes because the retransmission arrives.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let uas = std::thread::spawn(move || {
        let mut seen: HashMap<String, u32> = HashMap::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let branch = msg.top_via_branch().unwrap_or_default().to_owned();
                    let count = seen.entry(branch).or_insert(0);
                    *count += 1;
                    if *count >= 2 {
                        let _ = sock.send_to(&mirror_response(&msg, "200 OK", true), from);
                    } // first INVITE: deliberately ignored
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
    });
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-m",
        "1",
        "-d",
        "30",
        "-timeout",
        "20",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    assert!(err.contains("retrans-sent"), "{err}");
    drop(uas);
}

#[test]
fn actions_scenario_runs_against_scripted_uas() {
    // branching_actions expects optional 100 then 200 (no 180), so it needs a
    // responder that sends 100+200, not the generic 180+200 spawn_uas helper.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(Duration::from_secs(4)))
        .expect("timeout");
    let uas = std::thread::spawn(move || {
        let mut answered: HashMap<String, Vec<u8>> = HashMap::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let branch = msg.top_via_branch().unwrap_or_default().to_owned();
                    if let Some(ok) = answered.get(&branch) {
                        let _ = sock.send_to(ok, from);
                        continue;
                    }
                    let _ = sock.send_to(&mirror_response(&msg, "100 Trying", false), from);
                    let ok = mirror_response(&msg, "200 OK", true);
                    answered.insert(branch, ok.clone());
                    let _ = sock.send_to(&ok, from);
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
    });
    let scenario = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/crates/sipr-scenario/tests/corpus/positive/branching_actions.xml"
    );
    let out = run_sipr(&[
        "-sf",
        scenario,
        "-m",
        "3",
        "-d",
        "30",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 3 failed 0"), "{err}");
    drop(uas);
}

#[test]
fn digest_authentication_round_trips() {
    let (addr, registrar) = spawn_digest_registrar("sip.example.com", "alice", "secret");
    let scenario = r#"<scenario name="register-auth">
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:alice@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:alice@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 1 REGISTER
    Contact: <sip:alice@[local_ip]:[local_port]>
    Max-Forwards: 70
    Expires: 3600
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
    Authorization: [authentication username=alice password=secret]
    Max-Forwards: 70
    Expires: 3600
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let dir = std::env::temp_dir();
    let path = dir.join(format!("sipr-reg-{}.xml", std::process::id()));
    std::fs::write(&path, scenario).expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "sipr stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    assert!(
        registrar.join().expect("registrar thread"),
        "registrar must have accepted sipr's digest response"
    );
}

#[test]
fn digest_uri_matches_what_the_server_verifies() {
    // The digest URI sipr signs must equal the one it puts in the header,
    // or the registrar's recomputation (which reads uri= from the header)
    // would still pass while a real proxy keying on the request-URI fails.
    // Covered structurally by digest_authentication_round_trips; this is a
    // focused guard that the default URI (SIPp's `sip:remote_ip:remote_port`)
    // is signed and sent consistently.
    let (addr, registrar) = spawn_digest_registrar("r", "u", "p");
    let scenario = r#"<scenario name="reg">
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:u@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:u@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 1 REGISTER
    Content-Length: 0

  ]]></send>
  <recv response="401" auth="true"/>
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:u@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:u@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 2 REGISTER
    Authorization: [authentication username=u password=p]
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let path = std::env::temp_dir().join(format!("sipr-reg2-{}.xml", std::process::id()));
    std::fs::write(&path, scenario).expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(registrar.join().expect("registrar"));
}

#[test]
fn injection_file_fields_land_in_sent_messages() {
    // A UAS that captures the From user-part of each INVITE it sees, so we can
    // prove sipr substituted [field0] from the -inf file per call.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(Duration::from_secs(4)))
        .expect("timeout");
    let uas = std::thread::spawn(move || {
        let mut seen_users: Vec<String> = Vec::new();
        let mut answered: HashMap<String, Vec<u8>> = HashMap::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let branch = msg.top_via_branch().unwrap_or_default().to_owned();
                    if let Some(ok) = answered.get(&branch) {
                        let _ = sock.send_to(ok, from);
                        continue;
                    }
                    // Record the From header's user (between "sip:" and "@").
                    if let Some(from_h) = msg.header("From") {
                        if let Some(u) = from_h
                            .split("sip:")
                            .nth(1)
                            .and_then(|s| s.split('@').next())
                        {
                            seen_users.push(u.to_owned());
                        }
                    }
                    let ok = mirror_response(&msg, "200 OK", true);
                    answered.insert(branch, ok.clone());
                    let _ = sock.send_to(&ok, from);
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        seen_users
    });

    // A SEQUENTIAL injection file: three distinct user-parts.
    let inf = "SEQUENTIAL\nalice;1001\nbob;1002\ncarol;1003\n";
    let inf_path = std::env::temp_dir().join(format!("sipr-inf-{}.csv", std::process::id()));
    std::fs::write(&inf_path, inf).expect("write inf");

    let scenario = r#"<scenario name="inf-uac">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: <sip:[field0]@[local_ip]:[local_port]>
    X-Ext: [field1]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Content-Length: 0

  ]]></send>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let sc_path = std::env::temp_dir().join(format!("sipr-inf-sc-{}.xml", std::process::id()));
    std::fs::write(&sc_path, scenario).expect("write scenario");

    let out = run_sipr(&[
        "-sf",
        sc_path.to_str().expect("utf8"),
        "-inf",
        inf_path.to_str().expect("utf8"),
        "-m",
        "3",
        "-d",
        "30",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&sc_path);
    let _ = std::fs::remove_file(&inf_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 3 failed 0"), "{err}");

    let mut users = uas.join().expect("uas thread");
    users.sort();
    assert_eq!(
        users,
        vec!["alice", "bob", "carol"],
        "sequential fields per call"
    );
}

#[test]
fn lookup_reads_indexed_field_by_key() {
    // Prove the -infindex/lookup/[field line=[$var]] chain end to end: every
    // call looks up the fixed key "carol" in an indexed file and stamps her
    // number (1003) into a header — regardless of the call's own cycling line.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(Duration::from_secs(4)))
        .expect("timeout");
    let uas = std::thread::spawn(move || {
        let mut looked: Vec<String> = Vec::new();
        let mut answered: HashMap<String, Vec<u8>> = HashMap::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let branch = msg.top_via_branch().unwrap_or_default().to_owned();
                    if let Some(ok) = answered.get(&branch) {
                        let _ = sock.send_to(ok, from);
                        continue;
                    }
                    if let Some(h) = msg.header("X-Looked") {
                        looked.push(h.trim().to_owned());
                    }
                    let ok = mirror_response(&msg, "200 OK", true);
                    answered.insert(branch, ok.clone());
                    let _ = sock.send_to(&ok, from);
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        looked
    });

    let inf = "SEQUENTIAL\nalice;1001\nbob;1002\ncarol;1003\n";
    // SIPp keys files by basename, so the file must literally be users.csv;
    // give it a unique parent directory to avoid clashes between test runs.
    let inf_dir = std::env::temp_dir().join(format!("sipr-lk-{}", std::process::id()));
    std::fs::create_dir_all(&inf_dir).expect("mkdir");
    let inf_path = inf_dir.join("users.csv");
    std::fs::write(&inf_path, inf).expect("write inf");

    // A <nop> looks up "carol" -> her line; the INVITE reads field 1 of that
    // line via line=[$ln]. [field0] (the From user) still cycles per call.
    let scenario = r#"<scenario name="lookup-uac">
  <nop>
    <action>
      <lookup assign_to="ln" file="users.csv" key="carol"/>
    </action>
  </nop>
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: <sip:[field0]@[local_ip]:[local_port]>
    X-Looked: [field1 line=[$ln]]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Content-Length: 0

  ]]></send>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let sc_path = std::env::temp_dir().join(format!("sipr-lk-sc-{}.xml", std::process::id()));
    std::fs::write(&sc_path, scenario).expect("write scenario");

    let out = run_sipr(&[
        "-sf",
        sc_path.to_str().expect("utf8"),
        "-inf",
        inf_path.to_str().expect("utf8"),
        "-infindex",
        "users.csv",
        "0",
        "-m",
        "3",
        "-d",
        "30",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&sc_path);
    let _ = std::fs::remove_file(&inf_path);
    let _ = std::fs::remove_dir(&inf_dir);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 3 failed 0"), "{err}");

    let looked = uas.join().expect("uas thread");
    assert_eq!(
        looked,
        vec!["1003", "1003", "1003"],
        "every call looked up carol -> 1003"
    );
}

/// What a scripted TCP UAS observed.
#[derive(Default, Debug)]
struct TcpUasStats {
    invites: u64,
    byes: u64,
    saw_tcp_via: bool,
}

/// A scripted UAS speaking SIP over TCP: accept one connection, frame requests
/// off the stream, and reply on the same connection (180+200 to INVITE, 200 to
/// BYE). Returns once the peer closes or goes idle for `idle`.
fn spawn_tcp_uas(idle: Duration) -> (SocketAddr, std::thread::JoinHandle<TcpUasStats>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp uas");
    let addr = listener.local_addr().expect("addr");
    let handle = std::thread::spawn(move || {
        let mut stats = TcpUasStats::default();
        let Ok((mut stream, _peer)) = listener.accept() else {
            return stats;
        };
        stream.set_read_timeout(Some(idle)).ok();
        let mut framer = TcpFramer::new();
        let mut buf = [0u8; 16_384];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break, // peer closed
                Ok(n) => {
                    framer.push(&buf[..n]);
                    while let Some(raw) = framer.next_message() {
                        let Ok(msg) = Inbound::parse(&raw) else {
                            continue;
                        };
                        match msg.method() {
                            Some("INVITE") => {
                                stats.invites += 1;
                                if msg.header_lines("Via").iter().any(|v| v.contains("/TCP")) {
                                    stats.saw_tcp_via = true;
                                }
                                let ringing = mirror_response(&msg, "180 Ringing", true);
                                let ok = mirror_response(&msg, "200 OK", true);
                                let _ = stream.write_all(&ringing);
                                let _ = stream.write_all(&ok);
                            }
                            Some("BYE") => {
                                stats.byes += 1;
                                let ok = mirror_response(&msg, "200 OK", false);
                                let _ = stream.write_all(&ok);
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => break, // idle timeout or reset
            }
        }
        stats
    });
    (addr, handle)
}

#[test]
fn tcp_uac_places_call_over_stream() {
    // sipr as a TCP UAC (-t t1) dials the UAS, places one call over the single
    // stream connection, and completes with no retransmissions.
    let (addr, uas) = spawn_tcp_uas(Duration::from_secs(3));
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-t",
        "t1",
        "-m",
        "1",
        "-d",
        "20",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    // TCP carries no SIP retransmissions.
    assert!(err.contains("retrans-sent 0"), "{err}");
    let stats = uas.join().expect("tcp uas thread");
    assert_eq!(stats.invites, 1, "one INVITE framed off the stream");
    assert_eq!(stats.byes, 1, "call torn down with BYE");
    assert!(stats.saw_tcp_via, "[transport] rendered TCP in the Via");
}

#[test]
fn tcp_uas_answers_over_stream() {
    // sipr as a TCP UAS (-t t1): a scripted TCP client drives one INVITE dialog
    // and must get 180 then 200, and a 200 to its BYE, all over one connection.
    let port = TcpListener::bind("127.0.0.1:0")
        .expect("pick port")
        .local_addr()
        .expect("addr")
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .args([
            "-sn",
            "uas",
            "-t",
            "t1",
            "-p",
            &port.to_string(),
            "-timeout",
            "10",
            "-bg",
        ])
        .spawn()
        .expect("spawn sipr uas");

    // Connect once sipr has bound its listener.
    let mut stream = None;
    for _ in 0..80 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut stream = stream.expect("connect to sipr uas");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");

    let send = |stream: &mut TcpStream, method: &str, cseq: u32| {
        let msg = format!(
            "{method} sip:svc@127.0.0.1:{port} SIP/2.0\r\n\
             Via: SIP/2.0/TCP 127.0.0.1:55060;branch=z9hG4bK-tcp-{cseq}\r\n\
             From: <sip:caller@127.0.0.1>;tag=cli-tcp-1\r\n\
             To: <sip:svc@127.0.0.1:{port}>\r\n\
             Call-ID: tcp-call-1\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:caller@127.0.0.1:55060>\r\n\
             Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(msg.as_bytes()).expect("client write");
    };
    let read_statuses = |stream: &mut TcpStream, framer: &mut TcpFramer, until: u16| -> Vec<u16> {
        let mut buf = [0u8; 16_384];
        let mut seen = Vec::new();
        while !seen.contains(&until) {
            let Ok(n) = stream.read(&mut buf) else { break };
            if n == 0 {
                break;
            }
            framer.push(&buf[..n]);
            while let Some(raw) = framer.next_message() {
                if let Ok(m) = Inbound::parse(&raw) {
                    if let Some(code) = m.status_code() {
                        seen.push(code);
                    }
                }
            }
        }
        seen
    };

    let mut framer = TcpFramer::new();
    send(&mut stream, "INVITE", 1);
    let invite_statuses = read_statuses(&mut stream, &mut framer, 200);
    assert!(
        invite_statuses.contains(&180) && invite_statuses.contains(&200),
        "expected 180 and 200 to INVITE, got {invite_statuses:?}"
    );
    send(&mut stream, "ACK", 1);
    send(&mut stream, "BYE", 2);
    let bye_statuses = read_statuses(&mut stream, &mut framer, 200);
    assert!(
        bye_statuses.contains(&200),
        "expected 200 to BYE, got {bye_statuses:?}"
    );

    drop(stream);
    let _ = child.kill();
    let _ = child.wait();
}

// --------------------------------------------------------------------------
// TLS (`-t l1`): the TCP flows again, with a rustls layer in between.
// --------------------------------------------------------------------------

/// A fresh self-signed identity: PEM files (for the sipr process under test)
/// plus the in-memory DER pair (for scripted rustls peers).
struct TlsIdentity {
    _dir: tempfile::TempDir,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
}

fn tls_identity() -> TlsIdentity {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("key der");
    TlsIdentity {
        _dir: dir,
        cert_path,
        key_path,
        cert_der: cert.cert.der().clone(),
        key_der,
    }
}

fn ring_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::ring::default_provider())
}

/// Test-only "trust anything" verifier, mirroring SIPp's no-`-tls_ca` mode.
#[derive(Debug)]
struct AcceptAnyCert(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// What a scripted TLS UAS observed.
#[derive(Default, Debug)]
struct TlsUasStats {
    invites: u64,
    byes: u64,
    saw_tls_via: bool,
}

/// A scripted UAS speaking SIP over TLS: accept one connection, handshake,
/// frame requests off the decrypted stream, reply on the same connection.
fn spawn_tls_uas(
    identity: &TlsIdentity,
    idle: Duration,
) -> (SocketAddr, std::thread::JoinHandle<TlsUasStats>) {
    let server_config = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.cert_der.clone()],
            identity.key_der.clone_key(),
        )
        .expect("server config");
    let server_config = std::sync::Arc::new(server_config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls uas");
    let addr = listener.local_addr().expect("addr");
    let handle = std::thread::spawn(move || {
        let mut stats = TlsUasStats::default();
        let Ok((sock, _peer)) = listener.accept() else {
            return stats;
        };
        sock.set_read_timeout(Some(idle)).ok();
        let conn = rustls::ServerConnection::new(server_config).expect("server conn");
        let mut stream = rustls::StreamOwned::new(conn, sock);
        let mut framer = TcpFramer::new();
        let mut buf = [0u8; 16_384];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break, // peer closed
                Ok(n) => {
                    framer.push(&buf[..n]);
                    while let Some(raw) = framer.next_message() {
                        let Ok(msg) = Inbound::parse(&raw) else {
                            continue;
                        };
                        match msg.method() {
                            Some("INVITE") => {
                                stats.invites += 1;
                                if msg.header_lines("Via").iter().any(|v| v.contains("/TLS")) {
                                    stats.saw_tls_via = true;
                                }
                                let ringing = mirror_response(&msg, "180 Ringing", true);
                                let ok = mirror_response(&msg, "200 OK", true);
                                let _ = stream.write_all(&ringing);
                                let _ = stream.write_all(&ok);
                            }
                            Some("BYE") => {
                                stats.byes += 1;
                                let ok = mirror_response(&msg, "200 OK", false);
                                let _ = stream.write_all(&ok);
                            }
                            _ => {}
                        }
                    }
                }
                Err(_) => break, // idle timeout, reset, or TLS error
            }
        }
        stats
    });
    (addr, handle)
}

#[test]
fn tls_uac_places_call_over_stream() {
    // sipr as a TLS UAC (-t l1) handshakes with the UAS, places one call over
    // the encrypted stream, and completes with no retransmissions.
    let identity = tls_identity();
    let (addr, uas) = spawn_tls_uas(&identity, Duration::from_secs(3));
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-t",
        "l1",
        "-tls_cert",
        identity.cert_path.to_str().expect("utf8 path"),
        "-tls_key",
        identity.key_path.to_str().expect("utf8 path"),
        "-m",
        "1",
        "-d",
        "20",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    // TLS is reliable: no SIP retransmissions.
    assert!(err.contains("retrans-sent 0"), "{err}");
    let stats = uas.join().expect("tls uas thread");
    assert_eq!(stats.invites, 1, "one INVITE framed off the TLS stream");
    assert_eq!(stats.byes, 1, "call torn down with BYE");
    assert!(stats.saw_tls_via, "[transport] rendered TLS in the Via");
}

#[test]
fn tls_uas_answers_over_stream() {
    // sipr as a TLS UAS (-t l1): a scripted rustls client drives one INVITE
    // dialog and must get 180 then 200, and a 200 to its BYE.
    let identity = tls_identity();
    let port = TcpListener::bind("127.0.0.1:0")
        .expect("pick port")
        .local_addr()
        .expect("addr")
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .args([
            "-sn",
            "uas",
            "-t",
            "l1",
            "-tls_cert",
            identity.cert_path.to_str().expect("utf8 path"),
            "-tls_key",
            identity.key_path.to_str().expect("utf8 path"),
            "-p",
            &port.to_string(),
            "-timeout",
            "10",
            "-bg",
        ])
        .spawn()
        .expect("spawn sipr uas");

    // Connect once sipr has bound its listener.
    let mut sock = None;
    for _ in 0..80 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            sock = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let sock = sock.expect("connect to sipr uas");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let client_config = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert(ring_provider())))
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1").expect("name");
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(client_config), server_name)
        .expect("client conn");
    let mut stream = rustls::StreamOwned::new(conn, sock);

    type TlsClient = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;
    let send = |stream: &mut TlsClient, method: &str, cseq: u32| {
        let msg = format!(
            "{method} sip:svc@127.0.0.1:{port} SIP/2.0\r\n\
             Via: SIP/2.0/TLS 127.0.0.1:55061;branch=z9hG4bK-tls-{cseq}\r\n\
             From: <sip:caller@127.0.0.1>;tag=cli-tls-1\r\n\
             To: <sip:svc@127.0.0.1:{port}>\r\n\
             Call-ID: tls-call-1\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:caller@127.0.0.1:55061>\r\n\
             Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(msg.as_bytes()).expect("client write");
    };
    let read_statuses = |stream: &mut TlsClient, framer: &mut TcpFramer, until: u16| -> Vec<u16> {
        let mut buf = [0u8; 16_384];
        let mut seen = Vec::new();
        while !seen.contains(&until) {
            let Ok(n) = stream.read(&mut buf) else { break };
            if n == 0 {
                break;
            }
            framer.push(&buf[..n]);
            while let Some(raw) = framer.next_message() {
                if let Ok(m) = Inbound::parse(&raw) {
                    if let Some(code) = m.status_code() {
                        seen.push(code);
                    }
                }
            }
        }
        seen
    };

    let mut framer = TcpFramer::new();
    send(&mut stream, "INVITE", 1);
    let invite_statuses = read_statuses(&mut stream, &mut framer, 200);
    assert!(
        invite_statuses.contains(&180) && invite_statuses.contains(&200),
        "expected 180 and 200 to INVITE, got {invite_statuses:?}"
    );
    send(&mut stream, "ACK", 1);
    send(&mut stream, "BYE", 2);
    let bye_statuses = read_statuses(&mut stream, &mut framer, 200);
    assert!(
        bye_statuses.contains(&200),
        "expected 200 to BYE, got {bye_statuses:?}"
    );

    drop(stream);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn threepcc_controller_a_round_trips_a_command() {
    // sipr runs as 3PCC controller-A: it INVITEs a UDP UAS, captures a token
    // from the 200, <sendCmd>s it over the twin socket, <recvCmd>s the peer's
    // answer, and stamps it into the ACK. The test plays both the UDP UAS and
    // the twin peer. Proving X-Answer: WORLD reaches the ACK exercises the
    // whole SIP -> twin -> SIP path.

    // Twin socket (sipr-A dials this at startup, since sendCmd comes first).
    let twin = TcpListener::bind("127.0.0.1:0").expect("bind twin");
    let twin_addr = twin.local_addr().expect("twin addr");
    let twin_thread = std::thread::spawn(move || {
        let Ok((mut stream, _)) = twin.accept() else {
            return;
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("twin timeout");
        let mut framer = EscFramer::new();
        let mut buf = [0u8; 8192];
        while let Ok(n) = stream.read(&mut buf) {
            if n == 0 {
                break;
            }
            framer.push(&buf[..n]);
            if let Some(cmd) = framer.next_command() {
                // A's command carries "X-Offer: hello"; reply with the answer.
                assert!(cmd.contains("X-Offer: hello"), "got twin cmd: {cmd:?}");
                let reply = "Call-ID: c\r\nX-Answer: WORLD";
                stream.write_all(reply.as_bytes()).expect("twin reply");
                stream.write_all(&[0x1b]).expect("twin esc");
                stream.flush().ok();
                break;
            }
        }
    });

    // UDP UAS: 200 with a token, capture the ACK's X-Answer, answer BYE.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let uas_addr = sock.local_addr().expect("uas addr");
    sock.set_read_timeout(Some(Duration::from_secs(6)))
        .expect("timeout");
    let uas = std::thread::spawn(move || {
        let mut acked_answer: Option<String> = None;
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let mut ok = String::from("SIP/2.0 200 OK\r\n");
                    for h in msg.header_lines("Via") {
                        ok.push_str(h);
                        ok.push_str("\r\n");
                    }
                    for h in msg.header_lines("From") {
                        ok.push_str(h);
                        ok.push_str("\r\n");
                    }
                    let to = msg.header("To").unwrap_or_default();
                    ok.push_str(&format!("To: {to};tag=uas3pcc\r\n"));
                    ok.push_str(&format!(
                        "Call-ID: {}\r\n",
                        msg.call_id().unwrap_or_default()
                    ));
                    ok.push_str(&format!(
                        "CSeq: {}\r\n",
                        msg.header("CSeq").unwrap_or_default()
                    ));
                    ok.push_str("X-Token: hello\r\nContent-Length: 0\r\n\r\n");
                    let _ = sock.send_to(ok.as_bytes(), from);
                }
                Some("ACK") => {
                    acked_answer = msg.header("X-Answer").map(str::to_owned);
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                    break;
                }
                _ => {}
            }
        }
        acked_answer
    });

    let scenario = r#"<scenario name="3pcc-a">
  <send retrans="500"><![CDATA[
    INVITE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:a@[local_ip]:[local_port]>;tag=[pid]a[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: <sip:a@[local_ip]:[local_port]>
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200">
    <action><ereg regexp="X-Token: (.*)" search_in="msg" assign_to="1,2"/></action>
  </recv>
  <sendCmd><![CDATA[
    Call-ID: [call_id]
    X-Offer: [$2]
  ]]></sendCmd>
  <recvCmd>
    <action><ereg regexp="X-Answer: (.*)" search_in="msg" assign_to="3,4"/></action>
  </recvCmd>
  <send><![CDATA[
    ACK sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:a@[local_ip]:[local_port]>;tag=[pid]a[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    X-Answer: [$4]
    Content-Length: 0

  ]]></send>
  <send retrans="500"><![CDATA[
    BYE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:a@[local_ip]:[local_port]>;tag=[pid]a[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let sc_path = std::env::temp_dir().join(format!("sipr-3pcc-{}.xml", std::process::id()));
    std::fs::write(&sc_path, scenario).expect("write scenario");

    let out = run_sipr(&[
        "-sf",
        sc_path.to_str().expect("utf8"),
        "-3pcc",
        &twin_addr.to_string(),
        "-m",
        "1",
        "-d",
        "20",
        "-timeout",
        "15",
        "-bg",
        &uas_addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&sc_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");

    twin_thread.join().expect("twin thread");
    let answer = uas.join().expect("uas thread");
    assert_eq!(
        answer.as_deref(),
        Some("WORLD"),
        "twin answer must reach the ACK's X-Answer header"
    );
}

#[test]
fn users_closed_loop_binds_user_to_injection_line() {
    // -users 3 keeps 3 concurrent calls, each holding a stable 1-based user id.
    // A USER-mode -inf file maps user N -> line N-1, so every call's [field0]
    // must match its [userid] (1->alice, 2->bob, 3->carol). With -m 6, the
    // three users each run twice as the closed loop recycles them.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let uas_addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(Duration::from_secs(6)))
        .expect("timeout");
    let uas = std::thread::spawn(move || {
        // (userid, field0, users_total) captured from each distinct INVITE.
        let mut seen: Vec<(String, String, String)> = Vec::new();
        let mut answered: HashMap<String, Vec<u8>> = HashMap::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let branch = msg.top_via_branch().unwrap_or_default().to_owned();
                    if let Some(ok) = answered.get(&branch) {
                        let _ = sock.send_to(ok, from);
                        continue;
                    }
                    let uid = msg.header("X-User").unwrap_or_default().trim().to_owned();
                    let users = msg.header("X-Users").unwrap_or_default().trim().to_owned();
                    let field = msg
                        .header("From")
                        .and_then(|h| h.split("sip:").nth(1))
                        .and_then(|s| s.split('@').next())
                        .unwrap_or_default()
                        .to_owned();
                    seen.push((uid, field, users));
                    let ok = mirror_response(&msg, "200 OK", true);
                    answered.insert(branch, ok.clone());
                    let _ = sock.send_to(&ok, from);
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        seen
    });

    let inf = "USER\nalice\nbob\ncarol\n";
    let inf_dir = std::env::temp_dir().join(format!("sipr-users-{}", std::process::id()));
    std::fs::create_dir_all(&inf_dir).expect("mkdir");
    let inf_path = inf_dir.join("users.csv");
    std::fs::write(&inf_path, inf).expect("write inf");

    let scenario = r#"<scenario name="users-uac">
  <send retrans="500"><![CDATA[
    INVITE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[local_ip]:[local_port]>;tag=[pid]u[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: <sip:[field0]@[local_ip]:[local_port]>
    X-User: [userid]
    X-Users: [users]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[local_ip]:[local_port]>;tag=[pid]u[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Content-Length: 0

  ]]></send>
  <send retrans="500"><![CDATA[
    BYE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[local_ip]:[local_port]>;tag=[pid]u[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let sc_path = std::env::temp_dir().join(format!("sipr-users-sc-{}.xml", std::process::id()));
    std::fs::write(&sc_path, scenario).expect("write scenario");

    let out = run_sipr(&[
        "-sf",
        sc_path.to_str().expect("utf8"),
        "-inf",
        inf_path.to_str().expect("utf8"),
        "-users",
        "3",
        "-m",
        "6",
        "-d",
        "20",
        "-timeout",
        "15",
        "-bg",
        &uas_addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&sc_path);
    let _ = std::fs::remove_file(&inf_path);
    let _ = std::fs::remove_dir(&inf_dir);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 6 failed 0"), "{err}");

    let mut seen = uas.join().expect("uas thread");
    assert_eq!(seen.len(), 6, "six calls total from three recycled users");
    // Every call: [users] is 3, and [field0] matches the user id's row.
    let expected = |uid: &str| match uid {
        "1" => "alice",
        "2" => "bob",
        "3" => "carol",
        _ => "?",
    };
    for (uid, field, users) in &seen {
        assert_eq!(users, "3", "[users] must render the -users count");
        assert_eq!(field, expected(uid), "user {uid} must map to its row");
    }
    // Each user id ran exactly twice (closed-loop recycling).
    seen.sort();
    let ids: Vec<&str> = seen.iter().map(|(u, _, _)| u.as_str()).collect();
    assert_eq!(
        ids,
        vec!["1", "1", "2", "2", "3", "3"],
        "each user recycled once"
    );
}

#[test]
fn ipv6_uac_places_call_over_loopback() {
    // sipr places a call to an IPv6 target and must bracket [local_ip]/
    // [remote_ip] in URIs and Via. Skips where the host has no IPv6 loopback
    // (e.g. this build sandbox); runs for real anywhere ::1 binds.
    let Ok(sock) = UdpSocket::bind("[::1]:0") else {
        eprintln!("skip ipv6_uac_places_call_over_loopback: no IPv6 loopback");
        return;
    };
    let uas_addr = sock.local_addr().expect("addr"); // [::1]:port
    sock.set_read_timeout(Some(Duration::from_secs(6)))
        .expect("timeout");
    let uas = std::thread::spawn(move || {
        let mut saw_v6_uri = false;
        let mut answered: HashMap<String, Vec<u8>> = HashMap::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let branch = msg.top_via_branch().unwrap_or_default().to_owned();
                    if let Some(ok) = answered.get(&branch) {
                        let _ = sock.send_to(ok, from);
                        continue;
                    }
                    // Via and request-URI must carry the bracketed IPv6 literal.
                    let via_ok = msg.header_lines("Via").iter().any(|v| v.contains("[::1]"));
                    let uri_ok = msg.start_line().contains("@[::1]:");
                    saw_v6_uri = via_ok && uri_ok;
                    let ok = mirror_response(&msg, "200 OK", true);
                    answered.insert(branch, ok.clone());
                    let _ = sock.send_to(&ok, from);
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        saw_v6_uri
    });

    let out = run_sipr(&[
        "-sn",
        "uac",
        "-i",
        "::1",
        "-m",
        "1",
        "-d",
        "20",
        "-timeout",
        "15",
        "-bg",
        &uas_addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    assert!(
        uas.join().expect("uas thread"),
        "INVITE must bracket the IPv6 address in Via and request-URI"
    );
}

// ---- media: pcap replay ----------------------------------------------------

/// Like [`mirror_response`], but the 200 OK carries an SDP answer directing
/// audio to `media`, so sipr learns where to replay its pcap.
fn mirror_response_with_sdp(msg: &Inbound, status: &str, media: SocketAddr) -> Vec<u8> {
    let mut head = String::from_utf8(mirror_response(msg, status, true)).expect("utf8");
    let body = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n",
        ip = media.ip(),
        port = media.port()
    );
    head = head.replace(
        "Content-Length: 0\r\n\r\n",
        &format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ),
    );
    head.push_str(&body);
    head.into_bytes()
}

/// A UAS whose answers carry SDP pointing at `media`, plus the RTP sink
/// bound there. Returns (signaling addr, media addr, uas thread, sink thread
/// yielding every `(source, payload)` it received until idle).
#[allow(clippy::type_complexity)]
fn spawn_media_uas(
    idle: Duration,
) -> (
    SocketAddr,
    SocketAddr,
    std::thread::JoinHandle<UasStats>,
    std::thread::JoinHandle<Vec<(SocketAddr, Vec<u8>)>>,
) {
    let sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let media = sink.local_addr().expect("addr");
    sink.set_read_timeout(Some(idle)).expect("timeout");
    let sink_thread = std::thread::spawn(move || {
        let mut got = Vec::new();
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sink.recv_from(&mut buf) {
            got.push((from, buf[..n].to_vec()));
        }
        got
    });
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(idle)).expect("timeout");
    let uas_thread = std::thread::spawn(move || {
        let mut stats = UasStats::default();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    stats.invites += 1;
                    let _ = sock.send_to(&mirror_response(&msg, "180 Ringing", true), from);
                    let _ = sock.send_to(&mirror_response_with_sdp(&msg, "200 OK", media), from);
                }
                Some("BYE") => {
                    stats.byes += 1;
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        stats
    });
    (addr, media, uas_thread, sink_thread)
}

/// A pcap-playing UAC scenario: `[auto_media_port]` so concurrent calls get
/// distinct local ports, and the pause covers the capture's duration.
fn pcap_uac_scenario(pcap_path: &str) -> String {
    format!(
        r#"<scenario name="uac-pcap">
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
  <nop><action><exec play_pcap_audio="{pcap_path}"/></action></nop>
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
"#
    )
}

#[test]
fn play_pcap_audio_replays_capture_to_the_sdp_endpoint() {
    let (addr, _media, uas, sink) = spawn_media_uas(Duration::from_secs(2));
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let pcap_path = dir.join(format!("sipr-e2e-{pid}.pcap"));
    // 10 frames, 20 ms apart: 180 ms of "audio".
    let capture = sipr_media::pcap::build::rtp_capture(10, 20_000, 6000);
    std::fs::write(&pcap_path, &capture).expect("write pcap");
    let expected = sipr_media::pcap::parse(&capture).expect("parse");
    let scenario_path = dir.join(format!("sipr-e2e-{pid}.xml"));
    std::fs::write(
        &scenario_path,
        pcap_uac_scenario(pcap_path.to_str().expect("utf8")),
    )
    .expect("write scenario");
    let media_base = free_port_block(8);
    let out = run_sipr(&[
        "-sf",
        scenario_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-mp",
        &media_base.to_string(),
        "-r",
        "10",
        "-m",
        "2",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&pcap_path);
    let _ = std::fs::remove_file(&scenario_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 2 failed 0"), "{err}");
    assert!(err.contains("rtp-sent 20"), "{err}");
    let stats = uas.join().expect("uas");
    assert_eq!(stats.byes, 2, "{stats:?}");
    let got = sink.join().expect("sink");
    assert_eq!(got.len(), 20, "frames received: {}", got.len());
    // Every payload is a frame of the capture, verbatim.
    for (_, payload) in &got {
        assert!(
            expected.frames.iter().any(|f| f.payload == *payload),
            "unknown payload {payload:?}"
        );
    }
    // Two calls, two auto_media_port blocks: base and base+4, 10 frames each.
    let mut ports: Vec<u16> = got.iter().map(|(from, _)| from.port()).collect();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports, vec![media_base, media_base + 4], "{ports:?}");
    for p in ports {
        assert_eq!(got.iter().filter(|(f, _)| f.port() == p).count(), 10);
    }
}

#[test]
fn play_pcap_with_a_missing_file_is_fatal_at_startup() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let scenario_path = dir.join(format!("sipr-e2e-nopcap-{pid}.xml"));
    std::fs::write(&scenario_path, pcap_uac_scenario("does-not-exist.pcap")).expect("write");
    let out = run_sipr(&[
        "-sf",
        scenario_path.to_str().expect("utf8"),
        "-m",
        "1",
        "-timeout",
        "5",
        "-bg",
        "127.0.0.1:5",
    ]);
    let _ = std::fs::remove_file(&scenario_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("play_pcap_audio"), "{err}");
    assert!(err.contains("does-not-exist.pcap"), "{err}");
}

/// An `rtp_stream` + `play_dtmf` UAC: SDP advertises `[rtpstream_audio_port]`,
/// streams a raw file twice, then sends one DTMF digit.
fn rtp_stream_uac_scenario(file: &str) -> String {
    format!(
        r#"<scenario name="uac-rtp-stream">
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
    m=audio [rtpstream_audio_port] RTP/AVP 8 96
    a=rtcp:[rtpstream_audio_port+1]
    a=rtpmap:8 PCMA/8000
    a=rtpmap:96 telephone-event/8000

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
  <nop><action><exec rtp_stream="{file},2,8,PCMA/8000"/></action></nop>
  <pause milliseconds="300"/>
  <nop><action><exec play_dtmf="1,50"/></action></nop>
  <pause milliseconds="800"/>
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
"#
    )
}

#[test]
fn rtp_stream_and_play_dtmf_send_generated_rtp() {
    let (addr, _media, uas, sink) = spawn_media_uas(Duration::from_secs(2));
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    // 320 bytes of "audio" = two 160-byte PCMA packets per loop.
    let audio: Vec<u8> = (0..320u32).map(|i| (i % 251) as u8).collect();
    let audio_path = dir.join(format!("sipr-e2e-{pid}.g711a"));
    std::fs::write(&audio_path, &audio).expect("write audio");
    let scenario_path = dir.join(format!("sipr-e2e-rtp-{pid}.xml"));
    std::fs::write(
        &scenario_path,
        rtp_stream_uac_scenario(audio_path.to_str().expect("utf8")),
    )
    .expect("write scenario");
    let media_base = free_port();
    let out = run_sipr(&[
        "-sf",
        scenario_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-mp",
        &media_base.to_string(),
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&audio_path);
    let _ = std::fs::remove_file(&scenario_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    // 4 stream packets + a 1-digit DTMF burst of 20 noop + 3 start + 3 end.
    assert!(err.contains("rtp-sent 30"), "{err}");
    assert_eq!(uas.join().expect("uas").byes, 1);
    let got = sink.join().expect("sink");
    assert_eq!(got.len(), 30, "received {}", got.len());
    // Everything comes from the allocated [rtpstream_audio_port] = -mp base
    // (first allocation), which is also the plain [media_port] for DTMF.
    assert!(
        got.iter().all(|(from, _)| from.port() == media_base),
        "{got:?}"
    );
    let stream: Vec<&Vec<u8>> = got
        .iter()
        .map(|(_, p)| p)
        .filter(|p| p[1] & 0x7f == 8)
        .collect();
    assert_eq!(stream.len(), 4);
    for (i, p) in stream.iter().enumerate() {
        assert_eq!(u16::from_be_bytes([p[2], p[3]]), i as u16);
        assert_eq!(&p[8..12], &(0xCA11_0000u32).to_be_bytes(), "SSRC of call 1");
        let expected = if i % 2 == 0 {
            &audio[..160]
        } else {
            &audio[160..]
        };
        assert_eq!(&p[12..], expected, "packet {i} payload");
    }
    let noops = got.iter().filter(|(_, p)| p[1] & 0x7f == 97).count();
    let events: Vec<&Vec<u8>> = got
        .iter()
        .map(|(_, p)| p)
        .filter(|p| p[1] & 0x7f == 96)
        .collect();
    assert_eq!(noops, 20);
    assert_eq!(events.len(), 6);
    assert_eq!(
        events[0][1] & 0x80,
        0x80,
        "marker on the first event packet"
    );
    assert_eq!(&events[0][12..], &[1, 10, 0, 0]);
    assert_eq!(
        &events[5][12..],
        &[1, 0x8a, 0x01, 0x90],
        "end packet: digit 1, 50 ms"
    );
    let seqs: Vec<u16> = got
        .iter()
        .map(|(_, p)| p)
        .filter(|p| p[1] & 0x7f != 8)
        .map(|p| u16::from_be_bytes([p[2], p[3]]))
        .collect();
    assert_eq!(
        seqs,
        (1200..1226).collect::<Vec<u16>>(),
        "DTMF sequence from 1200"
    );
}

#[test]
fn rtp_stream_with_a_bad_payload_is_fatal_at_startup() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let scenario_path = dir.join(format!("sipr-e2e-badrtp-{pid}.xml"));
    std::fs::write(
        &scenario_path,
        rtp_stream_uac_scenario("x.raw").replace("x.raw,2,8,PCMA/8000", "x.raw,1,100"),
    )
    .expect("write");
    let out = run_sipr(&[
        "-sf",
        scenario_path.to_str().expect("utf8"),
        "-m",
        "1",
        "-timeout",
        "5",
        "-bg",
        "127.0.0.1:5",
    ]);
    let _ = std::fs::remove_file(&scenario_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("Missing mandatory payload_name"), "{err}");
}

// ---- AKA -------------------------------------------------------------------

/// A registrar that challenges with `AKAv1-MD5` using 3GPP TS 35.208 Test
/// Set 1 (nonce = base64(RAND || SQN⊕AK || AMF || MAC-A)) and verifies the
/// digest with RES as the password. Returns whether sipr authenticated.
fn spawn_aka_registrar(
    realm: &'static str,
    user: &'static str,
) -> (SocketAddr, std::thread::JoinHandle<bool>) {
    let (addr, h) = spawn_aka_registrar_with_sqn(realm, user, [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07]);
    let h2 = std::thread::spawn(move || h.join().expect("registrar").0);
    (addr, h2)
}

/// A registrar that challenges with `AKAv1-MD5` using 3GPP TS 35.208 Test
/// Set 1 keys and RAND, at sequence number `sqn`; verifies RES-password
/// digests, and handles `auts=` resynchronisation (RFC 3310 §3.2): the
/// AUTS is checked (SQN_MS recovered with AK*, MAC-S with AMF* = 0), the
/// digest must use the empty password, and a fresh challenge at SQN_MS + 1
/// follows. Returns `(authenticated, resynchronised)`.
#[allow(clippy::too_many_lines)]
fn spawn_aka_registrar_with_sqn(
    realm: &'static str,
    user: &'static str,
    sqn: [u8; 6],
) -> (SocketAddr, std::thread::JoinHandle<(bool, bool)>) {
    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }
    let k = hex::<16>("465b5ce8b199b49faa5f0a2ee238a6bc");
    let op = hex::<16>("cdc202d5123e20f62b6d676ac72cb318");
    let opc = sipr_auth::milenage::opc(&k, &op);
    let rand = hex::<16>("23553cbe9637a89d218ae64dae47bf35");
    let amf = hex::<2>("b9b9");
    let v = sipr_auth::milenage::f2345(&k, &opc, &rand);
    let res = v.res;
    let nonce_for = move |sqn: [u8; 6]| -> String {
        let mac = sipr_auth::milenage::f1(&k, &opc, &rand, &sqn, &amf);
        let mut bytes = rand.to_vec();
        bytes.extend(sqn.iter().zip(&v.ak).map(|(s, a)| s ^ a));
        bytes.extend_from_slice(&amf);
        bytes.extend_from_slice(&mac);
        sipr_auth::base64::encode(&bytes)
    };
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind registrar");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 65_535];
        let mut authenticated = false;
        let mut resynced = false;
        let mut sqn = sqn;
        let mut nonce = nonce_for(sqn);
        let challenge = |msg: &Inbound, nonce: &str| -> String {
            let mut r = String::from("SIP/2.0 401 Unauthorized\r\n");
            for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
                for l in msg.header_lines(name) {
                    r.push_str(l);
                    r.push_str("\r\n");
                }
            }
            r.push_str(&format!(
                "WWW-Authenticate: Digest realm=\"{realm}\", nonce=\"{nonce}\", \
                 algorithm=AKAv1-MD5, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n"
            ));
            r
        };
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            if msg.method() != Some("REGISTER") {
                continue;
            }
            let Some(auth) = msg.header("Authorization") else {
                let _ = sock.send_to(challenge(&msg, &nonce).as_bytes(), from);
                continue;
            };
            let field = |k: &str| -> Option<String> {
                auth.split(',').find_map(|p| {
                    let p = p.trim();
                    p.strip_prefix(&format!("{k}="))
                        .map(|v| v.trim_matches('"').to_owned())
                })
            };
            let uri = field("uri").unwrap_or_default();
            let cnonce = field("cnonce").unwrap_or_default();
            let nc = field("nc").unwrap_or_default();
            let expected_with = |password: &[u8]| -> String {
                let mut a1 = format!("{user}:{realm}:").into_bytes();
                a1.extend_from_slice(password);
                let ha1 = sipr_auth::md5_hex(&a1);
                let ha2 = sipr_auth::md5_hex(format!("REGISTER:{uri}").as_bytes());
                sipr_auth::md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes())
            };
            let got = field("response").unwrap_or_default();
            if let Some(auts_b64) = field("auts") {
                // Resynchronisation: verify AUTS, then re-challenge.
                let auts = sipr_auth::base64::decode(&auts_b64).unwrap_or_default();
                let ak_star = sipr_auth::milenage::f5_star(&k, &opc, &rand);
                let mut sqn_ms = [0u8; 6];
                let valid = auts.len() == 14 && {
                    for i in 0..6 {
                        sqn_ms[i] = auts[i] ^ ak_star[i];
                    }
                    let mac_s = sipr_auth::milenage::f1_star(&k, &opc, &rand, &sqn_ms, &[0, 0]);
                    auts[6..14] == mac_s && got == expected_with(b"")
                };
                if valid {
                    resynced = true;
                    // SQN_HE := SQN_MS + 1 (big-endian 48-bit).
                    let mut n = sqn_ms.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)) + 1;
                    for i in (0..6).rev() {
                        sqn[i] = (n & 0xff) as u8;
                        n >>= 8;
                    }
                    nonce = nonce_for(sqn);
                    let _ = sock.send_to(challenge(&msg, &nonce).as_bytes(), from);
                } else {
                    let mut r = String::from("SIP/2.0 403 Forbidden\r\n");
                    for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
                        for l in msg.header_lines(name) {
                            r.push_str(l);
                            r.push_str("\r\n");
                        }
                    }
                    r.push_str("Content-Length: 0\r\n\r\n");
                    let _ = sock.send_to(r.as_bytes(), from);
                }
                continue;
            }
            authenticated =
                got == expected_with(&res) && field("algorithm").as_deref() == Some("AKAv1-MD5");
            let mut r = format!(
                "SIP/2.0 {}\r\n",
                if authenticated {
                    "200 OK"
                } else {
                    "403 Forbidden"
                }
            );
            for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
                for l in msg.header_lines(name) {
                    r.push_str(l);
                    r.push_str("\r\n");
                }
            }
            r.push_str("Content-Length: 0\r\n\r\n");
            let _ = sock.send_to(r.as_bytes(), from);
            if authenticated {
                break;
            }
        }
        (authenticated, resynced)
    });
    (addr, handle)
}

fn aka_register_scenario(auth_params: &str) -> String {
    format!(
        r#"<scenario name="register-aka">
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:ims@[remote_ip]>;tag=[pid]a[call_number]
    To: <sip:ims@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 1 REGISTER
    Contact: <sip:ims@[local_ip]:[local_port]>
    Max-Forwards: 70
    Expires: 3600
    Content-Length: 0

  ]]></send>
  <recv response="401" auth="true"/>
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:ims@[remote_ip]>;tag=[pid]a[call_number]
    To: <sip:ims@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 2 REGISTER
    Contact: <sip:ims@[local_ip]:[local_port]>
    Authorization: [authentication {auth_params}]
    Max-Forwards: 70
    Expires: 3600
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#
    )
}

#[test]
fn aka_v1_md5_registration_round_trips() {
    let (addr, registrar) = spawn_aka_registrar("ims.example", "ims");
    let dir = std::env::temp_dir();
    let path = dir.join(format!("sipr-aka-{}.xml", std::process::id()));
    std::fs::write(
        &path,
        aka_register_scenario(
            "username=ims aka_K=0x465B5CE8B199B49FAA5F0A2EE238A6BC \
             aka_OP=0xCDC202D5123E20F62B6D676AC72CB318 aka_AMF=0xB9B9",
        ),
    )
    .expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "sipr stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    assert!(
        registrar.join().expect("registrar"),
        "registrar must accept sipr's AKA response"
    );
}

#[test]
fn aka_with_the_wrong_key_fails_the_call_not_the_process() {
    let (addr, registrar) = spawn_aka_registrar("ims.example", "ims");
    let dir = std::env::temp_dir();
    let path = dir.join(format!("sipr-aka-bad-{}.xml", std::process::id()));
    std::fs::write(
        &path,
        aka_register_scenario(
            "username=ims aka_K=0x00000000000000000000000000000000 \
             aka_OP=0xCDC202D5123E20F62B6D676AC72CB318",
        ),
    )
    .expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-m",
        "1",
        "-timeout",
        "5",
        "-bg",
        "-trace_err",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&path);
    let err = String::from_utf8_lossy(&out.stderr);
    // The call fails (MAC mismatch), the run completes and reports it.
    assert_eq!(out.status.code(), Some(1), "sipr stderr:\n{err}");
    assert!(err.contains("failed 1"), "{err}");
    drop(registrar);
    // Clean up the error trace sipr wrote in the CWD.
    for entry in std::fs::read_dir(".").into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("sipr-aka-bad-") && name.ends_with("_errors.log") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

// ---- runtime control ---------------------------------------------------------

/// Spawn sipr with `args` and a pipe for stderr, returning the child and a
/// reader thread collecting stderr.
fn spawn_sipr_bg(args: &[&str]) -> (std::process::Child, std::thread::JoinHandle<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .args(args)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sipr");
    let mut stderr = child.stderr.take().expect("stderr");
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    (child, reader)
}

fn wait_exit(child: &mut std::process::Child, limit: Duration) -> Option<i32> {
    let start = std::time::Instant::now();
    loop {
        if let Ok(Some(st)) = child.try_wait() {
            return st.code();
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn control_socket_speaks_sipp_protocol() {
    let (addr, uas) = spawn_uas(Duration::from_secs(3));
    let cp = free_port();
    let api_port = free_port();
    // 1 cps for 40 calls would take 40 s; "set rate 200" over the control
    // socket must finish it in a few, and "q" must drain rather than abort.
    // The HTTP API is the readiness signal: a control datagram sent before
    // sipr has bound its socket is silently lost (UDP).
    let (mut child, stderr) = spawn_sipr_bg(&[
        "-sn",
        "uac",
        "-r",
        "1",
        "-m",
        "40",
        "-d",
        "20",
        "-cp",
        &cp.to_string(),
        "--sipr-http",
        &api_port.to_string(),
        "-timeout",
        "30",
        "-bg",
        &addr.to_string(),
    ]);
    let api = SocketAddr::from(([127, 0, 0, 1], api_port));
    wait_for_api(api, &mut child, "control socket test");
    let ctl = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let target = SocketAddr::from(([127, 0, 0, 1], cp));
    ctl.send_to(b"cset rate 200\n", target).expect("send");
    ctl.send_to(b"cset bogus 1\n", target).expect("send");
    let code = wait_exit(&mut child, Duration::from_secs(15));
    let err = stderr.join().expect("stderr");
    assert_eq!(code, Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 40 failed 0"), "{err}");
    assert!(
        err.contains("control socket (UDP, SIPp -cp protocol) on 127.0.0.1:"),
        "{err}"
    );
    assert!(err.contains("Unknown set attribute: bogus"), "{err}");
    drop(uas);

    // A hot key: 'q' drains — the calls already placed complete, exit 0.
    let (addr, _uas) = spawn_uas(Duration::from_secs(3));
    let cp = free_port();
    let api_port = free_port();
    let (mut child, stderr) = spawn_sipr_bg(&[
        "-sn",
        "uac",
        "-r",
        "5",
        "-m",
        "1000",
        "-d",
        "20",
        "-cp",
        &cp.to_string(),
        "--sipr-http",
        &api_port.to_string(),
        "-timeout",
        "30",
        "-bg",
        &addr.to_string(),
    ]);
    // Quit once at least one call has been placed (so the drain has
    // something to complete and the exit code is 0, not 99), and keep
    // sending 'q' until sipr is gone: a soft quit is idempotent.
    let api = SocketAddr::from(([127, 0, 0, 1], api_port));
    wait_for_api(api, &mut child, "hot-key test");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let (_, body) = http(api, "GET", "/stats", "");
        if !body.contains("\"created\":0,") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let target = SocketAddr::from(([127, 0, 0, 1], cp));
    let code = loop {
        let _ = ctl.send_to(b"q\n", target);
        if let Ok(Some(st)) = child.try_wait() {
            break st.code();
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            break None;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let err = stderr.join().expect("stderr");
    assert_eq!(code, Some(0), "stderr:\n{err}");
    assert!(err.contains(" failed 0"), "{err}");
    assert!(
        !err.contains("successful 1000 "),
        "should have stopped early:\n{err}"
    );
}

/// Block until sipr's HTTP API at `api` accepts connections (its sockets
/// are all bound by then), or fail with sipr's stderr if it exited first.
fn wait_for_api(api: SocketAddr, child: &mut std::process::Child, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(api).is_ok() {
            return;
        }
        if let Ok(Some(st)) = child.try_wait() {
            panic!("{what}: sipr exited ({st}) before its API came up");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("{what}: HTTP API at {api} never came up");
}

/// Minimal HTTP client for the API tests.
fn http(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, String) {
    match try_http(addr, method, path, body) {
        Ok(r) => r,
        Err(e) => panic!("connect {addr}: {e}"),
    }
}

/// [`http`] that reports a connection failure instead of panicking, for
/// tests that can attach sipr's stderr to it.
fn try_http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> Result<(u16, String), std::io::Error> {
    use std::net::TcpStream;
    // The API listener may still be starting on a slow host: retry a
    // refused connection for a few seconds before giving up.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut s = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    };
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    let status: u16 = out.get(9..12).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = out.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    Ok((status, body))
}

#[test]
fn http_api_reports_stats_and_controls_the_run() {
    let (addr, _uas) = spawn_uas(Duration::from_secs(3));
    let port = free_port();
    let (mut child, stderr) = spawn_sipr_bg(&[
        "-sn",
        "uac",
        "-r",
        "2",
        "-m",
        "1000",
        "-d",
        "20",
        "-cp",
        "0",
        "--sipr-http",
        &port.to_string(),
        "-timeout",
        "30",
        "-bg",
        &addr.to_string(),
    ]);
    let api = SocketAddr::from(([127, 0, 0, 1], port));
    // Wait for the listener.
    let mut ready = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(api).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "HTTP API never came up");
    let (st, body) = http(api, "GET", "/health", "");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"status\":\"ok\""), "{body}");
    std::thread::sleep(Duration::from_millis(1500));
    let (st, body) = http(api, "GET", "/stats", "");
    assert_eq!(st, 200, "{body}");
    assert!(
        body.contains("\"scenario\":\"Basic Sipstone UAC\""),
        "{body}"
    );
    assert!(body.contains("\"role\":\"UAC\""), "{body}");
    assert!(body.contains("\"rate_target\":2"), "{body}");
    assert!(
        body.contains("\"steps\":[{\"hidden\":false,\"label\":"),
        "{body}"
    );
    let (st, body) = http(api, "POST", "/control", r#"{"rate": 150, "paused": false}"#);
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"rate\":150"), "{body}");
    assert!(body.contains("\"quitting\":\"no\""), "{body}");
    let (st, body) = http(api, "POST", "/control", r#"{"users": 3}"#);
    assert_eq!(st, 400, "{body}");
    assert!(body.contains("Users can not be changed"), "{body}");
    let (st, body) = http(api, "POST", "/command", r#"{"command":"set rate 300"}"#);
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"rate\":300"), "{body}");
    let (st, body) = http(api, "GET", "/scenario", "");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("send"), "{body}");
    let (st, body) = http(api, "POST", "/quit", r#"{"force": false}"#);
    assert_eq!(st, 202, "{body}");
    assert!(body.contains("\"quitting\":\"soft\""), "{body}");
    let code = wait_exit(&mut child, Duration::from_secs(10));
    let err = stderr.join().expect("stderr");
    assert_eq!(code, Some(0), "stderr:\n{err}");
    assert!(
        err.contains("HTTP control API on http://127.0.0.1:"),
        "{err}"
    );
    assert!(err.contains(" failed 0"), "{err}");
}

#[test]
fn http_api_off_loopback_needs_a_token() {
    let out = run_sipr(&[
        "-sn",
        "uas",
        "-cp",
        "0",
        "--sipr-http",
        "0.0.0.0:0",
        "-m",
        "1",
        "-timeout",
        "2",
        "-bg",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0));
    assert!(err.contains("--sipr-http-token"), "{err}");
}

// ---- RTP echo + rtpcheck -------------------------------------------------------

/// sipr against sipr: a `-rtp_echo` UAS echoes the UAC's pattern stream
/// back, and with a tolerance given the UAC judges the echo check.
#[test]
fn rtp_echo_uas_makes_the_uac_rtpcheck_pass() {
    let sip_port = free_port();
    let uas_media = free_port_block(4);
    let uac_media = free_port_block(4);
    let (mut uas, uas_err) = spawn_sipr_bg(&[
        "-sn",
        "uas",
        "-i",
        "127.0.0.1",
        "-p",
        &sip_port.to_string(),
        "-mi",
        "127.0.0.1",
        "-mp",
        &uas_media.to_string(),
        "-rtp_echo",
        "-cp",
        "0",
        "-m",
        "2",
        "-timeout",
        "20",
        "-bg",
    ]);
    std::thread::sleep(Duration::from_millis(400));
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let scenario_path = dir.join(format!("sipr-e2e-echo-{pid}.xml"));
    std::fs::write(
        &scenario_path,
        rtp_stream_uac_scenario("unused")
            .replace(
                r#"rtp_stream="unused,2,8,PCMA/8000""#,
                r#"rtp_stream="apattern,1,8""#,
            )
            .replace(
                r#"<nop><action><exec play_dtmf="1,50"/></action></nop>"#,
                "",
            ),
    )
    .expect("write");
    let out = run_sipr(&[
        "-sf",
        scenario_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-mp",
        &uac_media.to_string(),
        // 0.9: only a dead echo path (every check missed) fails; a loaded
        // CI host can miss half the 20 ms echo windows and must still pass.
        "-audiotolerance",
        "0.9",
        "-cp",
        "0",
        "-r",
        "5",
        "-m",
        "2",
        "-timeout",
        "20",
        "-bg",
        &format!("127.0.0.1:{sip_port}"),
    ]);
    let _ = std::fs::remove_file(&scenario_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "uac stderr:\n{err}");
    assert!(err.contains("successful 2 failed 0"), "{err}");
    assert!(err.contains("rtpcheck 0/2 failed"), "{err}");
    let code = wait_exit(&mut uas, Duration::from_secs(15));
    let uerr = uas_err.join().expect("uas stderr");
    assert_eq!(code, Some(0), "uas stderr:\n{uerr}");
    assert!(uerr.contains("RTP echo on 127.0.0.1:"), "{uerr}");
    assert!(uerr.contains(" echo "), "echo counters:\n{uerr}");
}

/// Without an echoing peer and with a tolerance given, the check fails
/// and the run exits with SIPp's -3 (253) even though the calls succeeded.
#[test]
fn rtpcheck_against_a_silent_peer_exits_253_when_a_tolerance_is_set() {
    let (addr, _uas, _media, _sink) = {
        let (a, m, u, s) = spawn_media_uas(Duration::from_secs(2));
        (a, u, m, s)
    };
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let scenario_path = dir.join(format!("sipr-e2e-nocheck-{pid}.xml"));
    let scenario = rtp_stream_uac_scenario("unused")
        .replace(
            r#"rtp_stream="unused,2,8,PCMA/8000""#,
            r#"rtp_stream="apattern,1,8""#,
        )
        .replace(
            r#"<nop><action><exec play_dtmf="1,50"/></action></nop>"#,
            "",
        );
    std::fs::write(&scenario_path, &scenario).expect("write");
    let base = &[
        "-sf",
        scenario_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-mp",
        &free_port().to_string(),
        "-cp",
        "0",
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
    ];
    // No tolerance: the sink swallows the RTP, nothing is judged, exit 0.
    let mut args: Vec<&str> = base.to_vec();
    let target = addr.to_string();
    args.push(&target);
    let out = run_sipr(&args);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(!err.contains("rtpcheck"), "{err}");
    // With a tolerance: judged and failed → 253.
    let mut args: Vec<&str> = base.to_vec();
    args.extend(["-audiotolerance", "1.0", &target]);
    let out = run_sipr(&args);
    let _ = std::fs::remove_file(&scenario_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(253), "{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    assert!(err.contains("rtpcheck 1/1 failed"), "{err}");
}

#[test]
fn rtp_echo_action_toggles_the_global_echo() {
    // Compiles (positive corpus covers the action); here: the engine warns
    // when the scenario toggles echo without -rtp_echo.
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let path = dir.join(format!("sipr-e2e-echotoggle-{pid}.xml"));
    std::fs::write(
        &path,
        r#"<scenario name="toggle"><recv request="INVITE"/><nop><action><rtp_echo value="0"/></action></nop></scenario>"#,
    )
    .expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-cp",
        "0",
        "-m",
        "1",
        "-timeout",
        "1",
        "-bg",
    ]);
    let _ = std::fs::remove_file(&path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("uses <rtp_echo> but -rtp_echo was not given"),
        "{err}"
    );
}

fn aka_resync_scenario(auth_params: &str) -> String {
    // REGISTER → 401 → REGISTER(auts) → 401 → REGISTER → 200
    let register = |cseq: u32, auth: &str| {
        format!(
            r#"  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:ims@[remote_ip]>;tag=[pid]a[call_number]
    To: <sip:ims@[remote_ip]>
    Call-ID: [call_id]
    CSeq: {cseq} REGISTER
    Contact: <sip:ims@[local_ip]:[local_port]>
{auth}    Max-Forwards: 70
    Expires: 3600
    Content-Length: 0

  ]]></send>
"#
        )
    };
    let auth_line = format!("    Authorization: [authentication {auth_params}]\n");
    format!(
        "<scenario name=\"register-aka-resync\">\n{}  <recv response=\"401\" auth=\"true\"/>\n{}  <recv response=\"401\" auth=\"true\"/>\n{}  <recv response=\"200\"/>\n</scenario>",
        register(1, ""),
        register(2, &auth_line),
        register(3, &auth_line)
    )
}

#[test]
fn aka_resynchronisation_round_trips() {
    // The registrar is at SQN ff9bb4d0b607; the client claims SQN_MS equal
    // to it, so the first challenge is out of range → AUTS → re-challenge
    // at SQN_MS + 1 → accepted.
    let (addr, registrar) =
        spawn_aka_registrar_with_sqn("ims.example", "ims", [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07]);
    let dir = std::env::temp_dir();
    let path = dir.join(format!("sipr-aka-resync-{}.xml", std::process::id()));
    std::fs::write(
        &path,
        aka_resync_scenario(
            "username=ims aka_K=0x465B5CE8B199B49FAA5F0A2EE238A6BC \
             aka_OP=0xCDC202D5123E20F62B6D676AC72CB318 aka_sqn=0xFF9BB4D0B607",
        ),
    )
    .expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-cp",
        "0",
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "sipr stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    let (authenticated, resynced) = registrar.join().expect("registrar");
    assert!(resynced, "registrar never saw a valid AUTS");
    assert!(
        authenticated,
        "registrar must accept the post-resync response"
    );
}

// ---- rate ramps ------------------------------------------------------------------

#[test]
fn rate_increase_ramps_the_rate_up() {
    let (addr, _uas) = spawn_uas(Duration::from_secs(3));
    // 1 cps would take 40 s for 40 calls; after one 1 s interval the ramp
    // makes it 201 cps and the run finishes in a few seconds.
    let start = std::time::Instant::now();
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-r",
        "1",
        "-rate_increase",
        "200",
        "-rate_interval",
        "1",
        "-m",
        "40",
        "-d",
        "20",
        "-cp",
        "0",
        "-timeout",
        "30",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 40 failed 0"), "{err}");
    assert!(
        start.elapsed() < Duration::from_secs(12),
        "ramp did not fire: {:?}",
        start.elapsed()
    );
}

#[test]
fn rate_max_quits_when_exceeded_unless_no_rate_quit() {
    let (addr, _uas) = spawn_uas(Duration::from_secs(3));
    // r=5, +5 every 1 s, max 5: t=1 s → 10 > 5 → clamp to 5 and drain, with
    // the first second's calls already placed (a run that placed nothing
    // would exit 99, as in SIPp).
    let start = std::time::Instant::now();
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-r",
        "5",
        "-rate_increase",
        "5",
        "-rate_max",
        "5",
        "-rate_interval",
        "1",
        "-m",
        "100000",
        "-d",
        "20",
        "-cp",
        "0",
        "-timeout",
        "30",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("rate reached -rate_max 5; quitting"), "{err}");
    assert!(err.contains(" failed 0"), "{err}");
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );

    // With -no_rate_quit the run keeps going at the cap until -m.
    let (addr, _uas) = spawn_uas(Duration::from_secs(3));
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-r",
        "1",
        "-rate_increase",
        "50",
        "-rate_max",
        "50",
        "-rate_interval",
        "300ms",
        "-no_rate_quit",
        "-m",
        "30",
        "-d",
        "20",
        "-cp",
        "0",
        "-timeout",
        "30",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 30 failed 0"), "{err}");
    assert!(!err.contains("quitting"), "{err}");
}

// ---- -auth_uri and rendered [authentication] parameters --------------------

/// `[authentication username=[field0] password=[field1]]`: SIPp renders each
/// parameter as a sub-message, so credentials can come from an -inf file.
#[test]
fn authentication_params_render_keywords() {
    let (addr, registrar) = spawn_digest_registrar("sip.example.com", "alice", "secret");
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let inf = dir.join(format!("sipr-authinf-{pid}.csv"));
    std::fs::write(&inf, "SEQUENTIAL\nalice;secret\n").expect("write inf");
    let scenario = r#"<scenario name="register-auth-inf">
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:[field0]@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 1 REGISTER
    Content-Length: 0

  ]]></send>
  <recv response="401" auth="true"/>
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:[field0]@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 2 REGISTER
    Authorization: [authentication username=[field0] password=[field1]]
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let path = dir.join(format!("sipr-authinf-{pid}.xml"));
    std::fs::write(&path, scenario).expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-inf",
        inf.to_str().expect("utf8"),
        "-cp",
        "0",
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&inf);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "sipr stderr:\n{err}");
    assert!(
        registrar.join().expect("registrar"),
        "credentials from [field0]/[field1] must verify"
    );
}

/// `-auth_uri`: the digest uri= is `sip:` + the value (SIPp), and by default
/// `sip:remote_ip:remote_port` — checked in the message trace.
#[test]
fn auth_uri_flag_and_default_follow_sipp() {
    fn uri_in_trace(extra: &[&str], expected_suffix: &str, addr: SocketAddr) {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let scenario = r#"<scenario name="reg-uri">
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:u@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:u@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 1 REGISTER
    Content-Length: 0

  ]]></send>
  <recv response="401" auth="true"/>
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:u@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:u@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 2 REGISTER
    Authorization: [authentication username=u password=p]
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
        let stem = format!("sipr-authuri-{pid}-{}", expected_suffix.len());
        let path = dir.join(format!("{stem}.xml"));
        std::fs::write(&path, scenario).expect("write");
        let mut args = vec![
            "-sf",
            path.to_str().expect("utf8"),
            "-cp",
            "0",
            "-m",
            "1",
            "-timeout",
            "15",
            "-bg",
            "-trace_msg",
        ];
        args.extend_from_slice(extra);
        let target = addr.to_string();
        args.push(&target);
        let out = run_sipr(&args);
        let _ = std::fs::remove_file(&path);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
        // The trace lands in the CWD as <stem>_<sipr pid>_messages.log.
        let mut found = None;
        for entry in std::fs::read_dir(".").into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&stem) && name.ends_with("_messages.log") {
                found = Some(std::fs::read_to_string(entry.path()).unwrap_or_default());
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let log = found.expect("message trace written");
        assert!(
            log.contains(&format!("uri=\"sip:{expected_suffix}\"")),
            "expected uri=\"sip:{expected_suffix}\" in:\n{log}"
        );
    }
    let (addr, registrar) = spawn_digest_registrar("r", "u", "p");
    uri_in_trace(&[], &addr.to_string(), addr);
    assert!(registrar.join().expect("registrar"));
    let (addr, registrar) = spawn_digest_registrar("r", "u", "p");
    uri_in_trace(&["-auth_uri", "ims.example.com"], "ims.example.com", addr);
    assert!(registrar.join().expect("registrar"));
}

// ---- hide / display ---------------------------------------------------------------

#[test]
fn hidden_steps_and_display_labels_reach_the_stats_api() {
    // A patient UAS: on the Windows runners sipr can take seconds to start,
    // and a UAS that has already given up turns the one call into a failure.
    let (addr, _uas) = spawn_uas(Duration::from_secs(15));
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let path = dir.join(format!("sipr-e2e-hide-{pid}.xml"));
    std::fs::write(
        &path,
        r#"<scenario name="hide">
  <send retrans="500" display="place call"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]h[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="180" optional="true"/>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]h[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Content-Length: 0

  ]]></send>
  <nop hide="true"/>
  <pause milliseconds="8000"/>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]h[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#,
    )
    .expect("write");
    let port = free_port();
    let (mut child, stderr) = spawn_sipr_bg(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-cp",
        "0",
        "--sipr-http",
        &port.to_string(),
        "-m",
        "1",
        "-timeout",
        "20",
        "-bg",
        &addr.to_string(),
    ]);
    let api = SocketAddr::from(([127, 0, 0, 1], port));
    let mut ready = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(api).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !ready {
        let _ = child.kill();
        let err = stderr.join().expect("stderr");
        panic!("HTTP API never came up; sipr stderr:\n{err}");
    }
    std::thread::sleep(Duration::from_millis(1500));
    // The call is in its 8 s pause here (long enough for the queries below
    // on a slow host; /quit ends the run); a sipr that has already exited
    // is the bug, and its stderr says why.
    if let Ok(Some(st)) = child.try_wait() {
        let err = stderr.join().expect("stderr");
        panic!("sipr exited early ({st}); stderr:\n{err}");
    }
    let (st, body) = match try_http(api, "GET", "/stats", "") {
        Ok(r) => r,
        Err(e) => {
            let _ = child.kill();
            let err = stderr.join().expect("stderr");
            panic!("GET /stats: {e}; sipr stderr:\n{err}");
        }
    };
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"label\":\"place call\""), "{body}");
    assert!(body.contains("\"hidden\":true"), "{body}");
    assert!(body.contains("\"hide\":true"), "{body}");
    let (st, body) = http(api, "POST", "/command", r#"{"command":"set hide false"}"#);
    assert_eq!(st, 200, "{body}");
    std::thread::sleep(Duration::from_millis(1200));
    let (_, body) = http(api, "GET", "/stats", "");
    assert!(body.contains("\"hide\":false"), "{body}");
    let _ = http(api, "POST", "/quit", r#"{"force": true}"#);
    let _ = wait_exit(&mut child, Duration::from_secs(10));
    let _ = stderr.join();
    let _ = std::fs::remove_file(&path);
}

// ---- SRTP -----------------------------------------------------------------------

/// An SRTP echo peer, doing what SIPp's `exec rtp_echo=startaudio` does:
/// answer the offer with its own SDES key, then unprotect each packet under
/// the caller's key and re-protect it under its own before echoing.
/// Returns (signaling addr, uas thread → BYEs seen, echo thread → packets
/// echoed).
#[allow(clippy::type_complexity)]
fn spawn_srtp_echo_uas(
    idle: Duration,
) -> (
    SocketAddr,
    std::thread::JoinHandle<u64>,
    std::thread::JoinHandle<u64>,
) {
    use sipr_media::{MasterKey, SrtpContext, Suite};
    use std::sync::{Arc, Mutex};
    let media_sock = UdpSocket::bind("127.0.0.1:0").expect("bind media");
    let media = media_sock.local_addr().expect("addr");
    media_sock.set_read_timeout(Some(idle)).expect("timeout");
    // Keys: ours (random-ish), the caller's (learned from the INVITE).
    let mut ours = [0u8; 30];
    for (i, b) in ours.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(53).wrapping_add(7);
    }
    let our_key = MasterKey::from_bytes(&ours);
    let contexts: Arc<Mutex<Option<(SrtpContext, SrtpContext)>>> = Arc::new(Mutex::new(None));
    let echo_ctx = Arc::clone(&contexts);
    let echo = std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        let mut echoed = 0u64;
        while let Ok((n, from)) = media_sock.recv_from(&mut buf) {
            let mut guard = echo_ctx.lock().expect("lock");
            let Some((rx, tx)) = guard.as_mut() else {
                continue;
            };
            let Ok(clear) = rx.unprotect(&buf[..n]) else {
                continue;
            };
            let wire = tx.protect(&clear);
            if media_sock.send_to(&wire, from).is_ok() {
                echoed += 1;
            }
        }
        echoed
    });
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(idle)).expect("timeout");
    let our_sdes = our_key.to_sdes();
    let uas = std::thread::spawn(move || {
        let mut byes = 0u64;
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    // Learn the caller's primary key and suite.
                    let attrs = sipr_media::sdp::crypto_attributes(msg.body(), "audio");
                    if let Some(a) = attrs.first()
                        && let (Some(suite), Some(key)) =
                            (Suite::parse(&a.suite), MasterKey::from_sdes(&a.key_params))
                    {
                        let rx = SrtpContext::new(suite, &key, a.unencrypted_srtp);
                        let tx = SrtpContext::new(suite, &our_key, false);
                        *contexts.lock().expect("lock") = Some((rx, tx));
                        let body = format!(
                            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                             m=audio {} RTP/AVP 0\r\na=crypto:{} {} inline:{our_sdes}\r\n",
                            media.port(),
                            a.tag,
                            a.suite
                        );
                        let mut r =
                            String::from_utf8(mirror_response(&msg, "200 OK", true)).expect("utf8");
                        r = r.replace(
                            "Content-Length: 0\r\n\r\n",
                            &format!(
                                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n",
                                body.len()
                            ),
                        );
                        r.push_str(&body);
                        let _ = sock.send_to(r.as_bytes(), from);
                    } else {
                        let _ = sock.send_to(
                            &mirror_response(&msg, "488 Not Acceptable Here", true),
                            from,
                        );
                    }
                }
                Some("BYE") => {
                    byes += 1;
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        byes
    });
    (addr, uas, echo)
}

/// sipr offers two SDES suites, streams a pattern under SRTP, and its echo
/// check passes against an SRTP echo peer that re-keys the echo.
#[test]
fn srtp_stream_passes_the_echo_check_against_an_srtp_echo_peer() {
    let (addr, uas, echo) = spawn_srtp_echo_uas(Duration::from_secs(2));
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let scenario_path = dir.join(format!("sipr-e2e-srtp-{pid}.xml"));
    let corpus = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/crates/sipr-scenario/tests/corpus/positive/srtp_sdes.xml"
    );
    // The corpus golden has a re-INVITE; this run only needs the first leg.
    let xml = std::fs::read_to_string(corpus).expect("corpus");
    let cut = xml.find("  <!-- re-INVITE").expect("marker");
    let mut scenario = xml[..cut].to_owned();
    scenario.push_str(
        r#"  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"#,
    );
    std::fs::write(&scenario_path, scenario).expect("write");
    let out = run_sipr(&[
        "-sf",
        scenario_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-mp",
        &free_port_block(4).to_string(),
        // 0.9: only a dead echo path (every check missed) fails; a loaded
        // CI host can miss half the 20 ms echo windows and must still pass.
        "-audiotolerance",
        "0.9",
        "-cp",
        "0",
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&scenario_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    assert!(err.contains("rtpcheck 0/1 failed"), "{err}");
    assert_eq!(uas.join().expect("uas"), 1);
    let echoed = echo.join().expect("echo");
    assert!(echoed >= 20, "echoed only {echoed} SRTP packets");
}

// ---- exec rtp_echo=: sipr as a per-call SRTP echo server (M25) ------------------

/// A sipr UAS runs a SIPp-style SRTP echo scenario (`exec rtp_echo=startaudio`
/// then `updateaudio`, keyed from the SDES answer) and a sipr UAC streaming
/// an SRTP pattern passes its echo check against it.
#[test]
fn srtp_echo_server_passes_a_peers_echo_check() {
    let sip_port = free_port();
    let uas_media = free_port_block(2);
    let corpus = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/crates/sipr-scenario/tests/corpus/positive/srtp_echo_uas.xml"
    );
    let (mut uas, uas_err) = spawn_sipr_bg(&[
        "-sf",
        corpus,
        "-i",
        "127.0.0.1",
        "-p",
        &sip_port.to_string(),
        "-mp",
        &uas_media.to_string(),
        "-m",
        "1",
        "-timeout",
        "20",
        "-bg",
    ]);
    std::thread::sleep(Duration::from_millis(400));
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let scenario_path = dir.join(format!("sipr-e2e-srtp-echo-{pid}.xml"));
    std::fs::write(
        &scenario_path,
        r#"<scenario name="uac-srtp-vs-echo-server">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]e[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Type: application/sdp
    Content-Length: [len]

    v=0
    o=sipr 0 0 IN IP[local_ip_type] [local_ip]
    s=-
    c=IN IP[media_ip_type] [media_ip]
    t=0 0
    m=audio [rtpstream_audio_port] RTP/AVP 0
    a=crypto:[cryptotag1audio] [cryptosuiteaescm128sha1801audio] inline:[cryptokeyparams1audio]
    a=rtpmap:0 PCMU/8000

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180"/>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]e[call_number]
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
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]e[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"#,
    )
    .expect("write scenario");
    let out = run_sipr(&[
        "-sf",
        scenario_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-mp",
        &free_port_block(2).to_string(),
        // 0.9: only a dead echo path (every check missed) fails; a loaded
        // CI host can miss half the 20 ms echo windows and must still pass.
        "-audiotolerance",
        "0.9",
        "-cp",
        "0",
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &format!("127.0.0.1:{sip_port}"),
    ]);
    let _ = std::fs::remove_file(&scenario_path);
    let uac_err = String::from_utf8_lossy(&out.stderr);
    let uas_code = wait_exit(&mut uas, Duration::from_secs(10));
    let uas_err = uas_err.join().expect("uas stderr");
    assert_eq!(out.status.code(), Some(0), "uac stderr:\n{uac_err}");
    assert!(uac_err.contains("rtpcheck 0/1 failed"), "{uac_err}");
    assert_eq!(uas_code, Some(0), "uas stderr:\n{uas_err}");
    assert!(uas_err.contains("successful 1 failed 0"), "{uas_err}");
}

/// An `rtp_echo` whose codec SIPp would not know fails at load, as SIPp's
/// parser does.
#[test]
fn rtp_echo_with_an_unknown_codec_fails_at_load() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let path = dir.join(format!("sipr-e2e-echo-codec-{pid}.xml"));
    std::fs::write(
        &path,
        r#"<scenario name="bad-echo">
  <recv request="INVITE"/>
  <nop><action><exec rtp_echo="startaudio,96,NOPE/8000"/></action></nop>
</scenario>"#,
    )
    .expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-p",
        "0",
    ]);
    let _ = std::fs::remove_file(&path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("rtp_echo"), "{err}");
}

// ---- per-call sockets: -t un / tn / ln, -max_socket (M28) ----------------------

/// What a recording UAS saw of each INVITE: the socket it came from and the
/// port the caller wrote in its Via (`[local_port]`).
#[derive(Debug, Clone)]
struct SeenInvite {
    source_ip: std::net::IpAddr,
    source_port: u16,
    via_ip: String,
    via_port: u16,
    request_line: String,
}

/// The host in a top Via's sent-by (`SIP/2.0/UDP HOST:port;...`).
fn via_host(msg: &sipr_net::Inbound) -> String {
    let via = msg.header("Via").unwrap_or_default();
    let sent_by = via.split_whitespace().nth(1).unwrap_or_default();
    let host_port = sent_by.split(';').next().unwrap_or_default();
    host_port
        .rsplit_once(':')
        .map_or(host_port, |(h, _)| h)
        .to_owned()
}

/// A second local IPv4 address (the primary interface's), for the per-IP
/// socket tests; `None` on a host with only loopback.
fn second_local_ipv4() -> Option<std::net::Ipv4Addr> {
    let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("10.255.255.255:9").ok()?;
    match probe.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => {
            // It must also be bindable (a VPN default route is not), and
            // traffic must flow between a loopback-bound socket and one
            // bound on it, both ways — that is what the per-IP tests do.
            // Windows' strong host model refuses that on the CI runners
            // ("network unreachable"), so those tests skip there.
            let lan_sock = UdpSocket::bind((v4, 0)).ok()?;
            let lo_sock = UdpSocket::bind("127.0.0.1:0").ok()?;
            let lan_addr = lan_sock.local_addr().ok()?;
            let lo_addr = lo_sock.local_addr().ok()?;
            let wait = Some(Duration::from_millis(500));
            lan_sock.set_read_timeout(wait).ok()?;
            lo_sock.set_read_timeout(wait).ok()?;
            let mut buf = [0u8; 8];
            lo_sock.send_to(b"probe", lan_addr).ok()?;
            lan_sock.recv_from(&mut buf).ok()?;
            lan_sock.send_to(b"probe", lo_addr).ok()?;
            lo_sock.recv_from(&mut buf).ok().map(|_| v4)
        }
        _ => None,
    }
}

/// The port in a top Via's sent-by (`SIP/2.0/UDP 127.0.0.1:PORT;...`).
fn via_port(msg: &sipr_net::Inbound) -> u16 {
    let via = msg.header("Via").unwrap_or_default();
    let sent_by = via.split_whitespace().nth(1).unwrap_or_default();
    let host_port = sent_by.split(';').next().unwrap_or_default();
    host_port
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

/// A minimal UDP UAS answering INVITE and BYE with 200 and recording where
/// each INVITE came from; returns after `calls` BYEs.
fn spawn_recording_udp_uas(calls: usize) -> (SocketAddr, std::thread::JoinHandle<Vec<SeenInvite>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut byes = 0;
        let mut buf = [0u8; 65_535];
        while byes < calls {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                break;
            };
            let Ok(msg) = sipr_net::Inbound::parse(&buf[..n]) else {
                continue;
            };
            let Some(method) = msg.method() else { continue };
            match method {
                "INVITE" => seen.push(SeenInvite {
                    source_ip: from.ip(),
                    source_port: from.port(),
                    via_ip: via_host(&msg),
                    via_port: via_port(&msg),
                    request_line: msg.start_line().to_owned(),
                }),
                "BYE" => byes += 1,
                _ => continue,
            }
            let reply = ok_reply(&msg, method == "INVITE");
            let _ = sock.send_to(reply.as_bytes(), from);
        }
        seen
    });
    (addr, handle)
}

/// A 200 OK echoing the dialog headers (a To tag for the INVITE).
fn ok_reply(msg: &sipr_net::Inbound, tag_to: bool) -> String {
    let mut out = String::from("SIP/2.0 200 OK\r\n");
    for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
        for line in msg.header_lines(name) {
            out.push_str(line);
            if name == "To" && tag_to && !line.contains("tag=") {
                out.push_str(";tag=uas1");
            }
            out.push_str("\r\n");
        }
    }
    out.push_str("Contact: <sip:uas@127.0.0.1>\r\nContent-Length: 0\r\n\r\n");
    out
}

/// A minimal TCP UAS: accepts connections, frames requests, answers INVITE
/// and BYE with 200 on the same connection; returns the number of
/// connections accepted once `calls` BYEs were answered.
fn spawn_counting_tcp_uas(calls: usize) -> (SocketAddr, std::thread::JoinHandle<usize>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind uas");
    let addr = listener.local_addr().expect("addr");
    listener.set_nonblocking(true).expect("nonblocking");
    let handle = std::thread::spawn(move || {
        let byes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut conns = 0;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while byes.load(std::sync::atomic::Ordering::Relaxed) < calls
            && std::time::Instant::now() < deadline
        {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // macOS accepted sockets inherit the listener's
                    // non-blocking mode; the reader wants to block.
                    let _ = stream.set_nonblocking(false);
                    conns += 1;
                    let byes = byes.clone();
                    std::thread::spawn(move || {
                        let mut framer = sipr_net::TcpFramer::new();
                        let mut buf = [0u8; 65_535];
                        while let Ok(n) = stream.read(&mut buf) {
                            if n == 0 {
                                break;
                            }
                            framer.push(&buf[..n]);
                            while let Some(raw) = framer.next_message() {
                                let Ok(msg) = sipr_net::Inbound::parse(&raw) else {
                                    continue;
                                };
                                let Some(method) = msg.method() else { continue };
                                if method == "ACK" {
                                    continue;
                                }
                                if method == "BYE" {
                                    byes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                let reply = ok_reply(&msg, method == "INVITE");
                                let _ = stream.write_all(reply.as_bytes());
                            }
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        conns
    });
    (addr, handle)
}

/// `-t un`: every call sends from its own UDP socket, and `[local_port]`
/// (the Via) names that socket's port — SIPp's `call_port`.
#[test]
fn udp_per_call_sockets_give_each_call_its_own_port() {
    let (addr, uas) = spawn_recording_udp_uas(3);
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-t",
        "un",
        "-i",
        "127.0.0.1",
        "-r",
        "10",
        "-m",
        "3",
        "-d",
        "300",
        "-timeout",
        "10",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    let seen = uas.join().expect("uas");
    assert_eq!(seen.len(), 3, "{seen:?}");
    let mut ports: Vec<u16> = seen.iter().map(|s| s.source_port).collect();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), 3, "calls must not share a socket: {seen:?}");
    for s in &seen {
        assert_eq!(
            s.via_port, s.source_port,
            "[local_port] must be the call socket's: {s:?}"
        );
    }
}

/// `-max_socket 1`: past the cap, calls share the open sockets
/// round-robin (SIPp's `new_sipp_call_socket` reuse).
#[test]
fn max_socket_makes_calls_share_sockets() {
    let (addr, uas) = spawn_recording_udp_uas(3);
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-t",
        "un",
        "-max_socket",
        "1",
        "-i",
        "127.0.0.1",
        "-r",
        "10",
        "-m",
        "3",
        "-d",
        "1000",
        "-timeout",
        "10",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    let seen = uas.join().expect("uas");
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert!(
        seen.iter().all(|s| s.source_port == seen[0].source_port),
        "all calls must share the one socket: {seen:?}"
    );
}

/// `-t tn`: one TCP connection per call.
#[test]
fn tcp_per_call_connections_one_per_call() {
    let (addr, uas) = spawn_counting_tcp_uas(2);
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-t",
        "tn",
        "-i",
        "127.0.0.1",
        "-r",
        "10",
        "-m",
        "2",
        "-d",
        "500",
        "-timeout",
        "10",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("one connection per call"), "{err}");
    assert_eq!(uas.join().expect("uas"), 2, "two calls, two connections");
}

/// `-t ln`: one TLS connection per call, against a sipr `l1` server.
#[test]
fn tls_per_call_connections_complete_calls() {
    let id = tls_identity();
    let port = free_port();
    let (mut uas, uas_err) = spawn_sipr_bg(&[
        "-sn",
        "uas",
        "-t",
        "l1",
        "-tls_cert",
        id.cert_path.to_str().expect("utf8"),
        "-tls_key",
        id.key_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-m",
        "2",
        "-timeout",
        "15",
        "-bg",
    ]);
    std::thread::sleep(Duration::from_millis(400));
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-t",
        "ln",
        "-tls_cert",
        id.cert_path.to_str().expect("utf8"),
        "-tls_key",
        id.key_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-r",
        "10",
        "-m",
        "2",
        "-d",
        "300",
        "-timeout",
        "10",
        "-bg",
        &format!("127.0.0.1:{port}"),
    ]);
    let uac_err = String::from_utf8_lossy(&out.stderr);
    let uas_code = wait_exit(&mut uas, Duration::from_secs(10));
    let uas_err = uas_err.join().expect("uas stderr");
    assert_eq!(
        out.status.code(),
        Some(0),
        "uac:\n{uac_err}\nuas:\n{uas_err}"
    );
    assert!(uac_err.contains("one connection per call"), "{uac_err}");
    assert_eq!(uas_code, Some(0), "uas:\n{uas_err}");
    assert!(uas_err.contains("successful 2 failed 0"), "{uas_err}");
}

// ---- -t s1|sn: SCTP (cargo feature `sctp`; needs an OS SCTP stack) (M32) --------

/// `-t s1` and `-t sn`: whole calls between a sipr SCTP UAS and UAC. Skips
/// where the host has no SCTP stack (macOS, Windows).
#[cfg(feature = "sctp")]
#[test]
fn sctp_mono_and_per_call_calls_complete() {
    if !sipr_net::sctp::available() {
        eprintln!("SKIPPED sctp_mono_and_per_call_calls_complete — no SCTP stack on this host.");
        return;
    }
    for mode in ["s1", "sn"] {
        let port = free_port();
        let (mut uas, uas_err) = spawn_sipr_bg(&[
            "-sn",
            "uas",
            "-t",
            "s1",
            "-i",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "2",
            "-timeout",
            "15",
            "-bg",
        ]);
        std::thread::sleep(Duration::from_millis(400));
        let out = run_sipr(&[
            "-sn",
            "uac",
            "-t",
            mode,
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
            "-bg",
            &format!("127.0.0.1:{port}"),
        ]);
        let uac_err = String::from_utf8_lossy(&out.stderr);
        let uas_code = wait_exit(&mut uas, Duration::from_secs(10));
        let uas_err = uas_err.join().expect("uas stderr");
        assert_eq!(
            out.status.code(),
            Some(0),
            "-t {mode} uac:\n{uac_err}\nuas:\n{uas_err}"
        );
        assert!(uac_err.contains("successful 2 failed 0"), "{uac_err}");
        assert_eq!(uas_code, Some(0), "uas:\n{uas_err}");
        assert!(uas_err.contains("successful 2 failed 0"), "{uas_err}");
    }
}

/// Without an SCTP stack, `-t s1` is a clear start-up error, like SIPp's
/// "SCTP support is not enabled!".
#[test]
fn sctp_without_a_stack_or_feature_is_a_clear_error() {
    #[cfg(feature = "sctp")]
    if sipr_net::sctp::available() {
        return; // covered by sctp_mono_and_per_call_calls_complete
    }
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-t",
        "s1",
        "-i",
        "127.0.0.1",
        "-m",
        "1",
        "127.0.0.1:5060",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0));
    assert!(err.contains("SCTP"), "{err}");
}

// ---- -t ui: one UDP socket per injected IP, -ip_field, [server_ip] (M31) --------

const UI_UAC: &str = r#"<scenario name="ui-uac">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [server_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[server_ip]:[local_port]>;tag=[pid]u[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: <sip:sipr@[server_ip]:[local_port]>
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [server_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[server_ip]:[local_port]>;tag=[pid]u[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <send retrans="500"><![CDATA[
    BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [server_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[server_ip]:[local_port]>;tag=[pid]u[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>
"#;

/// `-t ui` as a client: call N sends from the IP in its injection line
/// (SEQUENTIAL: loopback, the LAN address, loopback, ...), and
/// `[server_ip]` in its Via names that IP.
#[test]
fn ui_client_sends_each_call_from_its_lines_ip() {
    let Some(lan) = second_local_ipv4() else {
        eprintln!("SKIPPED ui_client_sends_each_call_from_its_lines_ip — no second local IPv4.");
        return;
    };
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let inf = dir.join(format!("sipr-e2e-ui-{pid}.csv"));
    std::fs::write(&inf, format!("SEQUENTIAL\n127.0.0.1;a\n{lan};b\n")).expect("write inf");
    let scenario = dir.join(format!("sipr-e2e-ui-{pid}.xml"));
    std::fs::write(&scenario, UI_UAC).expect("write scenario");
    let (addr, uas) = spawn_recording_udp_uas(4);
    let out = run_sipr(&[
        "-sf",
        scenario.to_str().expect("utf8"),
        "-t",
        "ui",
        "-inf",
        inf.to_str().expect("utf8"),
        "-ip_field",
        "0",
        "-r",
        "10",
        "-m",
        "4",
        "-timeout",
        "10",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&inf);
    let _ = std::fs::remove_file(&scenario);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    let seen = uas.join().expect("uas");
    assert_eq!(seen.len(), 4, "{seen:?}");
    let ips: Vec<String> = seen.iter().map(|s| s.source_ip.to_string()).collect();
    assert_eq!(
        ips,
        vec![
            "127.0.0.1".to_owned(),
            lan.to_string(),
            "127.0.0.1".to_owned(),
            lan.to_string()
        ],
        "{seen:?}"
    );
    for s in &seen {
        assert_eq!(
            s.via_ip,
            s.source_ip.to_string(),
            "[server_ip] must be the sending IP: {s:?}"
        );
        assert_eq!(
            s.via_port, s.source_port,
            "all per-IP sockets share the port: {s:?}"
        );
    }
}

/// `-t ui` as a server: bound on every listed IP, answering from the one
/// a request hit, with `[server_ip]` naming it.
#[test]
fn ui_server_answers_on_the_ip_the_request_hit() {
    let Some(lan) = second_local_ipv4() else {
        eprintln!("SKIPPED ui_server_answers_on_the_ip_the_request_hit — no second local IPv4.");
        return;
    };
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let inf = dir.join(format!("sipr-e2e-ui-uas-{pid}.csv"));
    std::fs::write(&inf, format!("SEQUENTIAL\n127.0.0.1\n{lan}\n")).expect("write inf");
    let scenario = dir.join(format!("sipr-e2e-ui-uas-{pid}.xml"));
    std::fs::write(
        &scenario,
        r#"<scenario name="ui-uas">
  <recv request="INVITE"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]SIPpTag01[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[server_ip]:[local_port]>
    Content-Length: 0

  ]]></send>
  <recv request="ACK"/>
</scenario>
"#,
    )
    .expect("write scenario");
    let port = free_port();
    let (mut uas, uas_err) = spawn_sipr_bg(&[
        "-sf",
        scenario.to_str().expect("utf8"),
        "-t",
        "ui",
        "-inf",
        inf.to_str().expect("utf8"),
        "-ip_field",
        "0",
        "-p",
        &port.to_string(),
        "-m",
        "2",
        "-timeout",
        "10",
        "-bg",
    ]);
    std::thread::sleep(Duration::from_millis(400));
    let caller = UdpSocket::bind("127.0.0.1:0").expect("bind caller");
    caller
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let cp = caller.local_addr().expect("addr").port();
    let mut buf = [0u8; 65_535];
    for (n, ip) in [lan.to_string(), "127.0.0.1".to_owned()].iter().enumerate() {
        let invite = format!(
            "INVITE sip:s@{ip}:{port} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{cp};branch=z9hG4bKui{n}\r\n\
             From: <sip:a@x>;tag=1\r\nTo: <sip:s@x>\r\nCall-ID: ui-{n}\r\nCSeq: 1 INVITE\r\n\
             Contact: <sip:a@127.0.0.1:{cp}>\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
        );
        let target: SocketAddr = format!("{ip}:{port}").parse().expect("addr");
        // No retransmission timer in a raw caller: resend until answered
        // (the UAS may still be starting); on silence, show the UAS's stderr.
        caller
            .set_read_timeout(Some(Duration::from_millis(700)))
            .expect("timeout");
        let mut got = None;
        for _ in 0..8 {
            caller
                .send_to(invite.as_bytes(), target)
                .expect("send invite");
            if let Ok(x) = caller.recv_from(&mut buf) {
                got = Some(x);
                break;
            }
        }
        let Some((len, from)) = got else {
            let _ = uas.kill();
            let err = uas_err.join().expect("uas stderr");
            panic!("no 200 OK from {target}; uas stderr:\n{err}");
        };
        let text = String::from_utf8_lossy(&buf[..len]);
        assert!(text.starts_with("SIP/2.0 200"), "{text}");
        assert_eq!(from, target, "answered from the socket the request hit");
        assert!(
            text.contains(&format!("Contact: <sip:{ip}:{port}>")),
            "[server_ip] must be that socket's IP:\n{text}"
        );
        let ack = format!(
            "ACK sip:s@{ip}:{port} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{cp};branch=z9hG4bKuia{n}\r\n\
             From: <sip:a@x>;tag=1\r\nTo: <sip:s@x>;tag=1\r\nCall-ID: ui-{n}\r\nCSeq: 1 ACK\r\n\
             Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
        );
        caller.send_to(ack.as_bytes(), target).expect("send ack");
    }
    let code = wait_exit(&mut uas, Duration::from_secs(10));
    let err = uas_err.join().expect("uas stderr");
    let _ = std::fs::remove_file(&inf);
    let _ = std::fs::remove_file(&scenario);
    assert_eq!(code, Some(0), "uas:\n{err}");
    assert!(err.contains("successful 2 failed 0"), "{err}");
}

// ---- TCP reconnection: -max_reconnect, -reconnect_close, -reconnect_sleep (M30) --

/// When the fake TCP UAS hangs up on its client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HangUp {
    /// After answering the first call's BYE (between calls).
    AfterFirstCall,
    /// Right after the first 200 OK to an INVITE (mid-call); later
    /// connections behave normally.
    AfterFirstInvite,
}

/// A TCP UAS that answers INVITE/BYE with 200 and closes the connection
/// once, per `policy`; returns the number of connections accepted after
/// `calls` BYEs (or a timeout).
fn spawn_hanging_up_tcp_uas(
    policy: HangUp,
    calls: usize,
) -> (SocketAddr, std::thread::JoinHandle<usize>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind uas");
    let addr = listener.local_addr().expect("addr");
    listener.set_nonblocking(true).expect("nonblocking");
    let handle = std::thread::spawn(move || {
        let byes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hung_up = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut conns = 0;
        let deadline = std::time::Instant::now() + Duration::from_secs(12);
        while byes.load(std::sync::atomic::Ordering::Relaxed) < calls
            && std::time::Instant::now() < deadline
        {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    conns += 1;
                    let byes = byes.clone();
                    let hung_up = hung_up.clone();
                    std::thread::spawn(move || {
                        let mut framer = sipr_net::TcpFramer::new();
                        let mut buf = [0u8; 65_535];
                        while let Ok(n) = stream.read(&mut buf) {
                            if n == 0 {
                                break;
                            }
                            framer.push(&buf[..n]);
                            while let Some(raw) = framer.next_message() {
                                let Ok(msg) = sipr_net::Inbound::parse(&raw) else {
                                    continue;
                                };
                                let Some(method) = msg.method() else { continue };
                                if method == "ACK" {
                                    continue;
                                }
                                let reply = ok_reply(&msg, method == "INVITE");
                                let _ = stream.write_all(reply.as_bytes());
                                let first = !hung_up.load(std::sync::atomic::Ordering::Relaxed);
                                let hang = match (policy, method) {
                                    (HangUp::AfterFirstInvite, "INVITE") => first,
                                    (HangUp::AfterFirstCall, "BYE") => first,
                                    _ => false,
                                };
                                if method == "BYE" {
                                    byes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                if hang {
                                    hung_up.store(true, std::sync::atomic::Ordering::Relaxed);
                                    let _ = stream.shutdown(std::net::Shutdown::Both);
                                    return;
                                }
                            }
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        conns
    });
    (addr, handle)
}

fn run_tcp_uac(
    addr: SocketAddr,
    extra: &[&str],
    calls: &str,
    pause_ms: &str,
) -> std::process::Output {
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
        calls,
        "-d",
        pause_ms,
        "-timeout",
        "12",
        "-bg",
    ];
    args.extend_from_slice(extra);
    let target = addr.to_string();
    args.push(&target);
    run_sipr(&args)
}

/// The peer closes the connection between calls. SIPp's order: the call
/// whose send finds the socket dead fails ("cannot send message"), the
/// socket is reset within the `-max_reconnect` budget ("Socket required a
/// reconnection."), and the calls after that complete on the new connection.
#[test]
fn reconnect_between_calls_with_budget() {
    let (addr, uas) = spawn_hanging_up_tcp_uas(HangUp::AfterFirstCall, 2);
    let out = run_tcp_uac(
        addr,
        &["-max_reconnect", "1", "-reconnect_sleep", "100"],
        "3",
        "200",
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr:\n{err}");
    assert!(err.contains("successful 2 failed 1"), "{err}");
    assert!(err.contains("socket required a reconnection"), "{err}");
    assert_eq!(uas.join().expect("uas"), 2, "one connection per dial");
}

/// Without a budget (SIPp's default `-max_reconnect 0`), a send on the dead
/// connection is fatal: "Max number of reconnections reached", exit 255.
#[test]
fn no_reconnect_budget_is_fatal_like_sipp() {
    let (addr, uas) = spawn_hanging_up_tcp_uas(HangUp::AfterFirstCall, 2);
    let out = run_tcp_uac(addr, &[], "2", "200");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255), "stderr:\n{err}");
    assert!(err.contains("Max number of reconnections reached"), "{err}");
    let _ = uas.join();
}

/// `-reconnect_close true` (the default): a connection that closes under a
/// live call fails that call at once ("Closing calls, because of TCP reset
/// or close!"). Here call 1 is mid-pause when the peer hangs up, and call 2
/// finds the socket dead: both fail.
#[test]
fn reconnect_close_fails_the_interrupted_call() {
    let (addr, uas) = spawn_hanging_up_tcp_uas(HangUp::AfterFirstInvite, 1);
    let out = run_tcp_uac(
        addr,
        &["-max_reconnect", "2", "-reconnect_sleep", "100"],
        "2",
        "1500",
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr:\n{err}");
    assert!(err.contains("successful 0 failed 2"), "{err}");
    let _ = uas.join();
}

/// `-reconnect_close false`: the interrupted call lives on, and once call 2's
/// failed send has reset the connection, call 1's BYE goes out on the new
/// one and is answered — SIPp's "resurrect the socket" comment.
#[test]
fn reconnect_close_false_keeps_the_interrupted_call() {
    let (addr, uas) = spawn_hanging_up_tcp_uas(HangUp::AfterFirstInvite, 1);
    let out = run_tcp_uac(
        addr,
        &[
            "-max_reconnect",
            "2",
            "-reconnect_sleep",
            "100",
            "-reconnect_close",
            "false",
        ],
        "2",
        "1500",
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 1"), "{err}");
    assert!(err.contains("socket required a reconnection"), "{err}");
    assert_eq!(
        uas.join().expect("uas"),
        2,
        "the BYE went out on the second connection"
    );
}

// ---- -rsa: remote sending address (M29) -----------------------------------------

/// `-rsa` as a UAC: every message goes to the sending address, while
/// `[remote_ip]:[remote_port]` in the request line still name the nominal
/// target (SIPp's `remote_ip`/`remote_port` globals).
#[test]
fn rsa_uac_sends_to_the_sending_address_but_renders_the_target() {
    let (rsa_addr, uas) = spawn_recording_udp_uas(1);
    let dead_target = free_port();
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-rsa",
        &rsa_addr.to_string(),
        "-i",
        "127.0.0.1",
        "-m",
        "1",
        "-d",
        "100",
        "-timeout",
        "10",
        "-bg",
        &format!("127.0.0.1:{dead_target}"),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    let seen = uas.join().expect("uas");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        seen[0]
            .request_line
            .contains(&format!("127.0.0.1:{dead_target} SIP/2.0")),
        "request line must name the nominal target: {}",
        seen[0].request_line
    );
}

/// `-rsa` as a UAS: responses go to the sending address from a socket of
/// their own (SIPp's `call_remote_socket`), not back to the request's source.
#[test]
fn rsa_uas_answers_towards_the_sending_address() {
    let rsa_sink = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    rsa_sink
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let rsa_addr = rsa_sink.local_addr().expect("addr");
    let port = free_port();
    let (mut uas, uas_err) = spawn_sipr_bg(&[
        "-sn",
        "uas",
        "-rsa",
        &rsa_addr.to_string(),
        "-i",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-m",
        "1",
        "-timeout",
        "6",
        "-bg",
    ]);
    std::thread::sleep(Duration::from_millis(300));
    let caller = UdpSocket::bind("127.0.0.1:0").expect("bind caller");
    caller
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("timeout");
    let invite = format!(
        "INVITE sip:s@127.0.0.1:{port} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{cp};branch=z9hG4bKrsa1\r\n\
         From: <sip:a@x>;tag=1\r\nTo: <sip:s@x>\r\nCall-ID: rsa-1\r\nCSeq: 1 INVITE\r\n\
         Contact: <sip:a@127.0.0.1:{cp}>\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        cp = caller.local_addr().expect("addr").port()
    );
    // A raw caller has no retransmission timer: resend until the sending
    // address hears a response (the UAS may still be starting).
    rsa_sink
        .set_read_timeout(Some(Duration::from_millis(700)))
        .expect("timeout");
    let mut buf = [0u8; 65_535];
    let mut got = None;
    for _ in 0..8 {
        caller
            .send_to(invite.as_bytes(), ("127.0.0.1", port))
            .expect("send invite");
        if let Ok(x) = rsa_sink.recv_from(&mut buf) {
            got = Some(x);
            break;
        }
    }
    let (n, from) = got.expect("the 180/200 must reach the rsa address");
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(
        text.starts_with("SIP/2.0 1") || text.starts_with("SIP/2.0 200"),
        "{text}"
    );
    assert_ne!(
        from.port(),
        port,
        "SIPp answers from a socket of its own, not -p"
    );
    assert!(
        caller.recv_from(&mut buf).is_err(),
        "the caller itself must receive nothing"
    );
    let _ = wait_exit(&mut uas, Duration::from_secs(10));
    let _ = uas_err.join();
}

/// `-rsa` over TCP as a UAS: the server dials the sending address and writes
/// its responses on that connection.
#[test]
fn rsa_tcp_uas_dials_the_sending_address() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind rsa listener");
    let rsa_addr = listener.local_addr().expect("addr");
    let port = free_port();
    let (mut uas, uas_err) = spawn_sipr_bg(&[
        "-sn",
        "uas",
        "-t",
        "t1",
        "-rsa",
        &rsa_addr.to_string(),
        "-i",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-m",
        "1",
        "-timeout",
        "6",
        "-bg",
    ]);
    std::thread::sleep(Duration::from_millis(300));
    let mut caller = None;
    for _ in 0..30 {
        if let Ok(c) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            caller = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut caller = caller.expect("connect uas");
    let invite = format!(
        "INVITE sip:s@127.0.0.1:{port} SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:{cp};branch=z9hG4bKrsa2\r\n\
         From: <sip:a@x>;tag=1\r\nTo: <sip:s@x>\r\nCall-ID: rsa-2\r\nCSeq: 1 INVITE\r\n\
         Contact: <sip:a@127.0.0.1:{cp};transport=tcp>\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        cp = caller.local_addr().expect("addr").port()
    );
    caller.write_all(invite.as_bytes()).expect("send invite");
    listener.set_nonblocking(false).expect("blocking");
    let (mut conn, _) = listener.accept().expect("uas must dial the rsa address");
    conn.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut buf = [0u8; 65_535];
    let n = conn.read(&mut buf).expect("response on the rsa connection");
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(
        text.starts_with("SIP/2.0 1") || text.starts_with("SIP/2.0 200"),
        "{text}"
    );
    let _ = wait_exit(&mut uas, Duration::from_secs(10));
    let _ = uas_err.join();
}

// ---- _unexp.main handler, pauserestore, jump variable=, closecon (M27) ---------

/// A UAC that sends an INFO in the middle of the UAS's pause, then expects
/// the UAS's BYE within `bye_timeout_ms` of its INFO round trip.
fn info_during_pause_uac(bye_timeout_ms: u32) -> String {
    format!(
        r#"<scenario name="uac-info-during-pause">
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

/// SIPp's `_unexp.main` recipe, from the corpus: an INFO arriving during
/// the UAS's 3 s pause is answered by the handler, which restores the
/// pause (`pauserestore`) and jumps back (`jump variable=`). The BYE the UAS
/// sends after the pause must arrive ~2.5 s after the INFO — a pause that
/// restarted from scratch would be ~3 s, so a 2.8 s timeout on the UAC's
/// BYE tells the two apart; the run must still last the full 3 s.
#[test]
fn unexp_handler_restores_the_interrupted_pause() {
    let corpus = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/crates/sipr-scenario/tests/corpus/positive/unexp_handler.xml"
    );
    let port = free_port();
    let (mut uas, uas_err) = spawn_sipr_bg(&[
        "-sf",
        corpus,
        "-i",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-m",
        "1",
        "-timeout",
        "20",
        "-bg",
    ]);
    std::thread::sleep(Duration::from_millis(300));
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let uac_path = dir.join(format!("sipr-e2e-unexp-uac-{pid}.xml"));
    std::fs::write(&uac_path, info_during_pause_uac(2800)).expect("write");
    let started = std::time::Instant::now();
    let out = run_sipr(&[
        "-sf",
        uac_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &format!("127.0.0.1:{port}"),
    ]);
    let elapsed = started.elapsed();
    let _ = std::fs::remove_file(&uac_path);
    let uac_err = String::from_utf8_lossy(&out.stderr);
    let uas_code = wait_exit(&mut uas, Duration::from_secs(10));
    let uas_err = uas_err.join().expect("uas stderr");
    assert_eq!(
        out.status.code(),
        Some(0),
        "uac:\n{uac_err}\nuas:\n{uas_err}"
    );
    assert_eq!(uas_code, Some(0), "uas:\n{uas_err}");
    assert!(uas_err.contains("successful 1 failed 0"), "{uas_err}");
    assert!(
        elapsed >= Duration::from_millis(2900),
        "the restored pause was cut short: {elapsed:?}"
    );
}

/// `<closecon/>` on the mono-socket TCP transport releases nothing
/// observable (SIPp's refcount semantics) — the call still completes.
#[test]
fn closecon_is_accepted_over_tcp() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let uas_path = dir.join(format!("sipr-e2e-closecon-{pid}.xml"));
    std::fs::write(
        &uas_path,
        r#"<scenario name="closecon-uas">
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
  <nop><action><closecon/></action></nop>
</scenario>
"#,
    )
    .expect("write");
    let port = free_port();
    let (mut uas, uas_err) = spawn_sipr_bg(&[
        "-sf",
        uas_path.to_str().expect("utf8"),
        "-t",
        "t1",
        "-i",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
    ]);
    std::thread::sleep(Duration::from_millis(300));
    let out = run_sipr(&[
        "-sn",
        "uac",
        "-t",
        "t1",
        "-i",
        "127.0.0.1",
        "-m",
        "1",
        "-d",
        "100",
        "-timeout",
        "10",
        "-bg",
        &format!("127.0.0.1:{port}"),
    ]);
    let _ = std::fs::remove_file(&uas_path);
    let uac_err = String::from_utf8_lossy(&out.stderr);
    let uas_code = wait_exit(&mut uas, Duration::from_secs(10));
    let uas_err = uas_err.join().expect("uas stderr");
    assert_eq!(
        out.status.code(),
        Some(0),
        "uac:\n{uac_err}\nuas:\n{uas_err}"
    );
    assert_eq!(uas_code, Some(0), "uas:\n{uas_err}");
    assert!(uas_err.contains("successful 1 failed 0"), "{uas_err}");
}

// ---- <verifyauth>: sipr as a digest-checking registrar (M26) -------------------

/// SIPp's documented registrar recipe (docs/scenarios/actions.rst): challenge,
/// then `<verifyauth>` on the re-sent REGISTER and branch on the boolean.
const VERIFYAUTH_UAS: &str = r#"<scenario name="verifyauth-registrar">
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

/// A UAC that registers with digest credentials and expects `expect`.
fn verifyauth_uac_scenario(password: &str, expect: u16) -> String {
    format!(
        r#"<scenario name="register-with-{password}">
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

/// Run the registrar for one call and a UAC against it; return both stderrs
/// and exit codes as (uac_code, uac_err, uas_code, uas_err).
fn run_verifyauth_pair(
    uas_xml: &str,
    uac_xml: &str,
    tag: &str,
) -> (Option<i32>, String, Option<i32>, String) {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let uas_path = dir.join(format!("sipr-e2e-verifyauth-uas-{tag}-{pid}.xml"));
    let uac_path = dir.join(format!("sipr-e2e-verifyauth-uac-{tag}-{pid}.xml"));
    std::fs::write(&uas_path, uas_xml).expect("write uas");
    std::fs::write(&uac_path, uac_xml).expect("write uac");
    let port = free_port();
    let (mut uas, uas_err) = spawn_sipr_bg(&[
        "-sf",
        uas_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
    ]);
    std::thread::sleep(Duration::from_millis(300));
    let out = run_sipr(&[
        "-sf",
        uac_path.to_str().expect("utf8"),
        "-i",
        "127.0.0.1",
        "-m",
        "1",
        "-timeout",
        "10",
        "-bg",
        &format!("127.0.0.1:{port}"),
    ]);
    let uas_code = wait_exit(&mut uas, Duration::from_secs(10));
    let _ = std::fs::remove_file(&uas_path);
    let _ = std::fs::remove_file(&uac_path);
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        uas_code,
        uas_err.join().expect("uas stderr"),
    )
}

#[test]
fn verifyauth_accepts_the_right_password_and_branches_to_200() {
    let (uac, uac_err, uas, uas_err) = run_verifyauth_pair(
        VERIFYAUTH_UAS,
        &verifyauth_uac_scenario("secret", 200),
        "good",
    );
    assert_eq!(uac, Some(0), "uac:\n{uac_err}\nuas:\n{uas_err}");
    assert_eq!(uas, Some(0), "uas:\n{uas_err}");
    assert!(uas_err.contains("successful 1 failed 0"), "{uas_err}");
}

#[test]
fn verifyauth_rejects_a_wrong_password_and_branches_to_403() {
    let (uac, uac_err, uas, uas_err) = run_verifyauth_pair(
        VERIFYAUTH_UAS,
        &verifyauth_uac_scenario("wrong", 403),
        "bad",
    );
    assert_eq!(uac, Some(0), "uac:\n{uac_err}\nuas:\n{uas_err}");
    assert_eq!(uas, Some(0), "uas:\n{uas_err}");
    assert!(uas_err.contains("successful 1 failed 0"), "{uas_err}");
}

// ---- [authentication] from an injection field, and SIPp's bare form ------------

/// SIPp's documented recipe (docs/scenarios/sipauth.rst): the CSV holds the
/// whole `[authentication …]` keyword and the scenario places `[field1]` on
/// a line of its own — the field is re-parsed as the keyword and renders the
/// full `Authorization:` header.
#[test]
fn authentication_keyword_from_an_injection_field() {
    let (addr, registrar) = spawn_digest_registrar("sip.example.com", "alice", "secret");
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let inf = dir.join(format!("sipr-authfield-{pid}.csv"));
    std::fs::write(
        &inf,
        "SEQUENTIAL\nalice;[authentication username=alice password=secret]\n",
    )
    .expect("write inf");
    let scenario = r#"<scenario name="register-auth-field">
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:[field0]@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 1 REGISTER
    Content-Length: 0

  ]]></send>
  <recv response="401" auth="true"/>
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:[field0]@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:[field0]@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 2 REGISTER
    [field1]
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let path = dir.join(format!("sipr-authfield-{pid}.xml"));
    std::fs::write(&path, scenario).expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-inf",
        inf.to_str().expect("utf8"),
        "-cp",
        "0",
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&inf);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "sipr stderr:\n{err}");
    assert!(
        registrar.join().expect("registrar"),
        "the injected [authentication] must verify"
    );
}

/// SIPp's own form: the keyword alone on a line renders the whole header,
/// `Proxy-Authorization:` when the challenge was a 407.
#[test]
fn bare_authentication_keyword_renders_the_full_header_line() {
    let (addr, registrar) = spawn_digest_registrar("r", "u", "p");
    let scenario = r#"<scenario name="reg-bare">
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:u@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:u@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 1 REGISTER
    Content-Length: 0

  ]]></send>
  <recv response="401" auth="true"/>
  <send retrans="500"><![CDATA[
    REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:u@[remote_ip]>;tag=[pid]r[call_number]
    To: <sip:u@[remote_ip]>
    Call-ID: [call_id]
    CSeq: 2 REGISTER
    [authentication username=u password=p]
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#;
    let path = std::env::temp_dir().join(format!("sipr-authbare-{}.xml", std::process::id()));
    std::fs::write(&path, scenario).expect("write");
    let out = run_sipr(&[
        "-sf",
        path.to_str().expect("utf8"),
        "-cp",
        "0",
        "-m",
        "1",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "sipr stderr:\n{err}");
    assert!(
        registrar.join().expect("registrar"),
        "the bare keyword must render Authorization:"
    );
}

// ---- out-of-call scenarios (M33) -------------------------------------------

/// The scripted UAS of [`run_uas`], which additionally probes the UAC with an
/// out-of-call OPTIONS (a fresh Call-ID) right after answering each INVITE,
/// and collects whatever comes back for those probes.
fn spawn_options_probing_uas(idle: Duration) -> (SocketAddr, std::thread::JoinHandle<Vec<String>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(idle)).expect("timeout");
    let handle = std::thread::spawn(move || {
        let mut probe_replies = Vec::new();
        let mut probes = 0u32;
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            if msg.status_code().is_some() {
                if msg.call_id().unwrap_or_default().starts_with("ooc-probe-") {
                    probe_replies.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                }
                continue;
            }
            match msg.method() {
                Some("INVITE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "180 Ringing", true), from);
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", true), from);
                    probes += 1;
                    let options = format!(
                        "OPTIONS sip:sipr@{from} SIP/2.0\r\n\
                         Via: SIP/2.0/UDP {addr};branch=z9hG4bK-probe-{probes}\r\n\
                         From: probe <sip:probe@{addr}>;tag=probe{probes}\r\n\
                         To: <sip:sipr@{from}>\r\n\
                         Call-ID: ooc-probe-{probes}@{}\r\n\
                         CSeq: 7 OPTIONS\r\n\
                         Max-Forwards: 70\r\n\
                         Content-Length: 0\r\n\r\n",
                        addr.ip()
                    );
                    let _ = sock.send_to(options.as_bytes(), from);
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        probe_replies
    });
    (addr, handle)
}

/// Run sipr in `dir` (so its trace files land there) and return the output
/// plus the contents of its `*_errors.log`.
fn run_sipr_in(dir: &std::path::Path, args: &[&str]) -> (std::process::Output, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("spawn sipr");
    let errors = std::fs::read_dir(dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with("_errors.log"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    (out, errors)
}

/// A UAC with `-oocsn ooc_default` answers an OPTIONS of no known call with
/// a 200 mirroring the request's headers, and the main flow is unaffected;
/// without an ooc scenario the OPTIONS is discarded and counted; with
/// `ooc_dummy` it spawns a call that fails on the ooc stats and stays
/// unanswered (SIPp `socket.cpp` `process_message`).
#[test]
fn uac_answers_out_of_call_options_with_ooc_scenario() {
    let dir = std::env::temp_dir().join(format!("sipr-ooc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let run = |ooc: Option<&str>| {
        let (addr, uas) = spawn_options_probing_uas(Duration::from_secs(2));
        let target = addr.to_string();
        let mut args = vec![
            "-sn",
            "uac",
            "-i",
            "127.0.0.1",
            "-m",
            "2",
            "-d",
            "300",
            "-timeout",
            "15",
            "-trace_err",
        ];
        if let Some(name) = ooc {
            args.extend(["-oocsn", name]);
        }
        args.push(&target);
        let (out, errors) = run_sipr_in(&dir, &args);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(0), "ooc={ooc:?} stderr:\n{stderr}");
        assert!(
            stderr.contains("successful 2 failed 0"),
            "ooc={ooc:?}\n{stderr}"
        );
        let replies = uas.join().expect("uas");
        for f in std::fs::read_dir(&dir).expect("readdir").flatten() {
            let _ = std::fs::remove_file(f.path());
        }
        (stderr, errors, replies)
    };

    // ooc_default: every probe gets a 200 with the copied headers.
    let (stderr, errors, replies) = run(Some("ooc_default"));
    assert_eq!(
        replies.len(),
        2,
        "probe replies:\n{replies:?}\nstderr:\n{stderr}"
    );
    for (i, reply) in replies.iter().enumerate() {
        let n = i + 1;
        assert!(reply.starts_with("SIP/2.0 200 OK\r\n"), "{reply}");
        assert!(
            reply.contains(&format!(";branch=z9hG4bK-probe-{n}\r\n")),
            "{reply}"
        );
        assert!(reply.contains(&format!(">;tag=probe{n}\r\n")), "{reply}");
        assert!(reply.contains("\r\nTo: <sip:sipr@"), "{reply}");
        assert!(
            reply.contains(&format!("\r\nCall-ID: ooc-probe-{n}@")),
            "{reply}"
        );
        assert!(reply.contains("\r\nCSeq: 7 OPTIONS\r\n"), "{reply}");
        assert!(reply.contains("\r\nContact: <sip:127.0.0.1:"), "{reply}");
        assert!(reply.contains(";transport=UDP>\r\n"), "{reply}");
        assert!(reply.ends_with("Content-Length: 0\r\n\r\n"), "{reply}");
    }
    assert!(
        errors.contains("Received out-of-call OPTIONS message, using the out-of-call scenario"),
        "{errors}"
    );
    // The main scenario's counters see nothing unexpected.
    assert!(stderr.contains(" unexpected 0 "), "{stderr}");

    // No ooc scenario: SIPp's default — discard and count.
    let (stderr, errors, replies) = run(None);
    assert!(replies.is_empty(), "unexpected replies:\n{replies:?}");
    assert!(stderr.contains(" unexpected 2 "), "{stderr}");
    assert!(errors.contains("out-of-call message ignored"), "{errors}");

    // ooc_dummy: the probe spawns an ooc call that fails on the ooc stats;
    // nothing is answered and the main counters stay clean.
    let (stderr, errors, replies) = run(Some("ooc_dummy"));
    assert!(replies.is_empty(), "unexpected replies:\n{replies:?}");
    assert!(stderr.contains(" unexpected 0 "), "{stderr}");
    assert!(
        errors.contains("Received out-of-call OPTIONS message, using the out-of-call scenario"),
        "{errors}"
    );
    assert!(
        errors.contains("unexpected OPTIONS for call ooc-probe-1@"),
        "{errors}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `set display ooc` (control socket) swaps every screen to the out-of-call
/// scenario — visible through the HTTP API's `display`, `role`, `steps` and
/// counters — and `set display main` swaps them back (SIPp's `screen.cpp`
/// reads `display_scenario->stats` throughout).
#[test]
fn set_display_ooc_swaps_the_scenario_screen() {
    let (addr, _uas) = // A patient UAS and exit wait: the shared macOS CI runners can
    // starve the 1 cps pacer for seconds at a time.
    spawn_uas(Duration::from_secs(10));
    let cp = free_port();
    let port = free_port();
    let (mut child, stderr) = spawn_sipr_bg(&[
        "-sn",
        "uac",
        "-oocsn",
        "ooc_default",
        "-r",
        "1",
        "-m",
        "6",
        "-d",
        "20",
        "-cp",
        &cp.to_string(),
        "--sipr-http",
        &port.to_string(),
        "-timeout",
        "30",
        "-bg",
        &addr.to_string(),
    ]);
    let api = SocketAddr::from(([127, 0, 0, 1], port));
    let mut ready = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(api).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "HTTP API never came up");
    let ctl = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let target = SocketAddr::from(([127, 0, 0, 1], cp));
    std::thread::sleep(Duration::from_millis(1200));
    let (st, body) = http(api, "GET", "/stats", "");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"display\":\"main\""), "{body}");
    assert!(body.contains("\"label\":\"send INVITE\""), "{body}");

    ctl.send_to(b"cset display ooc\n", target).expect("send");
    std::thread::sleep(Duration::from_millis(1500));
    let (st, body) = http(api, "GET", "/stats", "");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"display\":\"ooc\""), "{body}");
    assert!(body.contains("\"mixed\":false"), "{body}");
    assert!(body.contains("\"role\":\"UAS\""), "{body}");
    assert!(body.contains("\"label\":\"recv .*\""), "{body}");
    assert!(body.contains("\"label\":\"send 200\""), "{body}");
    assert!(!body.contains("\"label\":\"send INVITE\""), "{body}");
    // The counters follow: nothing has reached the ooc scenario.
    assert!(body.contains("\"created\":0,"), "{body}");

    ctl.send_to(b"cset display main\n", target).expect("send");
    std::thread::sleep(Duration::from_millis(1500));
    let (st, body) = http(api, "GET", "/stats", "");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"display\":\"main\""), "{body}");
    assert!(body.contains("\"role\":\"UAC\""), "{body}");
    assert!(body.contains("\"label\":\"send INVITE\""), "{body}");
    assert!(!body.contains("\"created\":0,"), "{body}");

    let code = wait_exit(&mut child, Duration::from_secs(30));
    let err = stderr.join().expect("stderr");
    assert_eq!(code, Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 6 failed 0"), "{err}");
}

/// A UDP peer for mixed mode: it answers sipr's calls like [`spawn_uas`]
/// and, on the first ACK it gets, originates one call of its own towards
/// sipr (INVITE → expects 180/200 → ACK → BYE → expects 200). Returns the
/// responses sipr sent to that call, in order.
fn spawn_mixed_peer(idle: Duration) -> (SocketAddr, std::thread::JoinHandle<Vec<String>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(idle)).expect("timeout");
    let handle = std::thread::spawn(move || {
        let mut rx_responses = Vec::new();
        let mut originated = false;
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            if let Some(code) = msg.status_code() {
                if !msg.call_id().unwrap_or_default().starts_with("rx-call-") {
                    continue;
                }
                rx_responses.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let cseq = msg.header("CSeq").unwrap_or_default();
                if code == 200 && cseq.ends_with("INVITE") {
                    // Established: ACK it, then hang up straight away.
                    let to = msg.header("To").unwrap_or_default();
                    let dialog = |method: &str, cseq: u32, branch: &str| {
                        format!(
                            "{method} sip:sipr@{from} SIP/2.0\r\n\
                             Via: SIP/2.0/UDP {addr};branch=z9hG4bK-rx-{branch}\r\n\
                             From: peer <sip:peer@{addr}>;tag=peer1\r\n\
                             To: {to}\r\n\
                             Call-ID: rx-call-1@{}\r\n\
                             CSeq: {cseq} {method}\r\n\
                             Max-Forwards: 70\r\n\
                             Content-Length: 0\r\n\r\n",
                            addr.ip()
                        )
                    };
                    let _ = sock.send_to(dialog("ACK", 1, "ack").as_bytes(), from);
                    let _ = sock.send_to(dialog("BYE", 2, "bye").as_bytes(), from);
                }
                continue;
            }
            match msg.method() {
                Some("INVITE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "180 Ringing", true), from);
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", true), from);
                }
                Some("ACK") if !originated => {
                    originated = true;
                    let invite = format!(
                        "INVITE sip:sipr@{from} SIP/2.0\r\n\
                         Via: SIP/2.0/UDP {addr};branch=z9hG4bK-rx-1\r\n\
                         From: peer <sip:peer@{addr}>;tag=peer1\r\n\
                         To: <sip:sipr@{from}>\r\n\
                         Call-ID: rx-call-1@{}\r\n\
                         CSeq: 1 INVITE\r\n\
                         Contact: <sip:peer@{addr}>\r\n\
                         Max-Forwards: 70\r\n\
                         Content-Length: 0\r\n\r\n",
                        addr.ip()
                    );
                    let _ = sock.send_to(invite.as_bytes(), from);
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        rx_responses
    });
    (addr, handle)
}

/// Mixed mode: a UAC with `-rxsn uas` terminates the call the peer
/// originates towards it (180, 200, then 200 to the BYE, all with the
/// copied headers) while its own calls run clean; without `-rxs*` the
/// INVITE is discarded and counted (SIPp `socket.cpp` `MODE_MIXED`).
#[test]
fn uac_terminates_incoming_calls_with_rx_scenario() {
    let dir = std::env::temp_dir().join(format!("sipr-rx-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let run = |rx: bool| {
        let (addr, peer) = spawn_mixed_peer(Duration::from_secs(2));
        let target = addr.to_string();
        let mut args = vec![
            "-sn",
            "uac",
            "-i",
            "127.0.0.1",
            "-m",
            "2",
            "-d",
            "300",
            "-timeout",
            "15",
            "-trace_err",
        ];
        if rx {
            args.extend(["-rxsn", "uas"]);
        }
        args.push(&target);
        let (out, errors) = run_sipr_in(&dir, &args);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(0), "rx={rx} stderr:\n{stderr}");
        assert!(
            stderr.contains("successful 2 failed 0"),
            "rx={rx}\n{stderr}"
        );
        let responses = peer.join().expect("peer");
        for f in std::fs::read_dir(&dir).expect("readdir").flatten() {
            let _ = std::fs::remove_file(f.path());
        }
        (stderr, errors, responses)
    };

    // With the receive scenario: 180, 200 (INVITE), 200 (BYE).
    let (stderr, errors, responses) = run(true);
    let statuses: Vec<&str> = responses
        .iter()
        .map(|r| r.lines().next().unwrap_or_default())
        .collect();
    assert_eq!(
        statuses,
        ["SIP/2.0 180 Ringing", "SIP/2.0 200 OK", "SIP/2.0 200 OK"],
        "responses:\n{responses:?}\nstderr:\n{stderr}"
    );
    let ok_invite = &responses[1];
    assert!(
        ok_invite.contains(";branch=z9hG4bK-rx-1\r\n"),
        "{ok_invite}"
    );
    assert!(ok_invite.contains(">;tag=peer1\r\n"), "{ok_invite}");
    assert!(ok_invite.contains("\r\nTo: <sip:sipr@"), "{ok_invite}");
    assert!(ok_invite.contains("\r\nCSeq: 1 INVITE\r\n"), "{ok_invite}");
    assert!(
        ok_invite.contains("\r\nContact: <sip:127.0.0.1:"),
        "{ok_invite}"
    );
    let ok_bye = &responses[2];
    assert!(ok_bye.contains(";branch=z9hG4bK-rx-bye\r\n"), "{ok_bye}");
    assert!(ok_bye.contains("\r\nCSeq: 2 BYE\r\n"), "{ok_bye}");
    assert!(
        errors.contains("Received INVITE for no known call, using the receive scenario"),
        "{errors}"
    );
    // The main scenario's counters see nothing unexpected.
    assert!(stderr.contains(" unexpected 0 "), "{stderr}");

    // No receive scenario: SIPp's client-mode default — discard and count.
    let (stderr, errors, responses) = run(false);
    assert!(responses.is_empty(), "unexpected responses:\n{responses:?}");
    assert!(stderr.contains(" unexpected 1 "), "{stderr}");
    assert!(errors.contains("out-of-call message ignored"), "{errors}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-rxinf` files join the injection table after the `-inf` ones: the
/// receive scenario reads one by name, and its bare `[fieldN]` still reads
/// the first `-inf` file (SIPp's `default_file`).
#[test]
fn rx_scenario_reads_rxinf_by_file_name() {
    let dir = std::env::temp_dir().join(format!("sipr-rxinf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let xml = dir.join("rx.xml");
    std::fs::write(
        &xml,
        r#"<scenario name="rx-fields">
  <recv request="INVITE"/>
  <send><![CDATA[
    SIP/2.0 200 OK
    [last_Via:]
    [last_From:]
    [last_To:];tag=[pid]RxTag[call_number]
    [last_Call-ID:]
    [last_CSeq:]
    Contact: <sip:[local_ip]:[local_port];transport=[transport]>
    X-Rx-User: [field0 file=rx.csv]
    X-Main-User: [field1]
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
</scenario>"#,
    )
    .expect("write scenario");
    let main_csv = dir.join("main.csv");
    let rx_csv = dir.join("rx.csv");
    std::fs::write(&main_csv, "SEQUENTIAL\nm0;m1\n").expect("write csv");
    std::fs::write(&rx_csv, "SEQUENTIAL\nalice;\n").expect("write csv");
    let (addr, peer) = spawn_mixed_peer(Duration::from_secs(2));
    let (out, _errors) = run_sipr_in(
        &dir,
        &[
            "-sn",
            "uac",
            "-rxsf",
            xml.to_str().expect("utf8"),
            "-inf",
            main_csv.to_str().expect("utf8"),
            "-rxinf",
            rx_csv.to_str().expect("utf8"),
            "-i",
            "127.0.0.1",
            "-m",
            "2",
            "-d",
            "300",
            "-timeout",
            "15",
            &addr.to_string(),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "stderr:\n{stderr}");
    assert!(stderr.contains("successful 2 failed 0"), "{stderr}");
    let responses = peer.join().expect("peer");
    let _ = std::fs::remove_dir_all(&dir);
    let ok_invite = responses
        .iter()
        .find(|r| r.starts_with("SIP/2.0 200 OK") && r.contains("CSeq: 1 INVITE"))
        .unwrap_or_else(|| panic!("no 200 to the INVITE:\n{responses:?}"));
    assert!(
        ok_invite.contains("\r\nX-Rx-User: alice\r\n"),
        "{ok_invite}"
    );
    assert!(ok_invite.contains("\r\nX-Main-User: m1\r\n"), "{ok_invite}");
}

/// `set display rx` (control socket) swaps every screen to the receive
/// scenario — the HTTP API's `display`, `role`, `steps` and counters — and
/// `set display main` swaps them back; `mixed` is on throughout.
#[test]
fn set_display_rx_swaps_the_screens() {
    let (addr, _uas) = // A patient UAS and exit wait: the shared macOS CI runners can
    // starve the 1 cps pacer for seconds at a time.
    spawn_uas(Duration::from_secs(10));
    let cp = free_port();
    let port = free_port();
    let (mut child, stderr) = spawn_sipr_bg(&[
        "-sn",
        "uac",
        "-rxsn",
        "uas",
        "-r",
        "1",
        "-m",
        "6",
        "-d",
        "20",
        "-cp",
        &cp.to_string(),
        "--sipr-http",
        &port.to_string(),
        "-timeout",
        "30",
        "-bg",
        &addr.to_string(),
    ]);
    let api = SocketAddr::from(([127, 0, 0, 1], port));
    let mut ready = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(api).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "HTTP API never came up");
    let ctl = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let target = SocketAddr::from(([127, 0, 0, 1], cp));
    std::thread::sleep(Duration::from_millis(1200));
    let (st, body) = http(api, "GET", "/stats", "");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"display\":\"main\""), "{body}");
    assert!(body.contains("\"mixed\":true"), "{body}");
    assert!(body.contains("\"role\":\"UAC\""), "{body}");
    assert!(body.contains("\"label\":\"send INVITE\""), "{body}");

    ctl.send_to(b"cset display rx\n", target).expect("send");
    std::thread::sleep(Duration::from_millis(1500));
    let (st, body) = http(api, "GET", "/stats", "");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"display\":\"rx\""), "{body}");
    assert!(body.contains("\"mixed\":true"), "{body}");
    assert!(body.contains("\"role\":\"UAS\""), "{body}");
    assert!(
        body.contains("\"scenario\":\"Basic UAS responder\""),
        "{body}"
    );
    assert!(body.contains("\"label\":\"recv INVITE\""), "{body}");
    assert!(body.contains("\"label\":\"send 180\""), "{body}");
    assert!(!body.contains("\"label\":\"send INVITE\""), "{body}");
    // The counters follow: nobody has called us.
    assert!(body.contains("\"created\":0,"), "{body}");

    ctl.send_to(b"cset display main\n", target).expect("send");
    std::thread::sleep(Duration::from_millis(1500));
    let (st, body) = http(api, "GET", "/stats", "");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"display\":\"main\""), "{body}");
    assert!(body.contains("\"role\":\"UAC\""), "{body}");
    assert!(body.contains("\"label\":\"send INVITE\""), "{body}");
    assert!(!body.contains("\"created\":0,"), "{body}");

    let code = wait_exit(&mut child, Duration::from_secs(30));
    let err = stderr.join().expect("stderr");
    assert_eq!(code, Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 6 failed 0"), "{err}");
}

// ---- <User>/<Global> variable scopes and user-id retirement (M35) ---------

/// A UAC scenario that counts its calls per user (`<User>`) and per run
/// (`<Global>`) and reports both, the user id and a `-set`-able global in
/// INVITE headers.
fn counter_uac_scenario() -> String {
    r#"<scenario name="counters">
  <Global variables="per_run,region"/>
  <User variables="per_user"/>
  <nop>
    <action>
      <add assign_to="per_user" value="1"/>
      <add assign_to="per_run" value="1"/>
    </action>
  </nop>
  <send retrans="500"><![CDATA[
    INVITE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:u[userid]@[local_ip]:[local_port]>;tag=[pid]c[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: <sip:u[userid]@[local_ip]:[local_port]>
    X-User: [userid]
    X-User-Count: [$per_user]
    X-Run-Count: [$per_run]
    X-Region: [$region]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <send><![CDATA[
    ACK sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:u[userid]@[local_ip]:[local_port]>;tag=[pid]c[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Content-Length: 0

  ]]></send>
  <pause/>
  <send retrans="500"><![CDATA[
    BYE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:u[userid]@[local_ip]:[local_port]>;tag=[pid]c[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#
        .to_owned()
}

/// One INVITE as the counter scenario reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CounterCall {
    user: String,
    per_user: u32,
    per_run: u32,
    region: String,
}

/// A UAS that answers the counter scenario and records each distinct
/// INVITE's headers in arrival order.
fn spawn_counter_uas(idle: Duration) -> (SocketAddr, std::thread::JoinHandle<Vec<CounterCall>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(idle)).expect("timeout");
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut answered: HashMap<String, Vec<u8>> = HashMap::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let branch = msg.top_via_branch().unwrap_or_default().to_owned();
                    if let Some(ok) = answered.get(&branch) {
                        let _ = sock.send_to(ok, from);
                        continue;
                    }
                    let header =
                        |name: &str| msg.header(name).unwrap_or_default().trim().to_owned();
                    // Doubles render as SIPp's `%lf` ("2.000000").
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let count = |name: &str| header(name).parse::<f64>().map_or(0, |n| n as u32);
                    seen.push(CounterCall {
                        user: header("X-User"),
                        per_user: count("X-User-Count"),
                        per_run: count("X-Run-Count"),
                        region: header("X-Region"),
                    });
                    let ok = mirror_response(&msg, "200 OK", true);
                    answered.insert(branch, ok.clone());
                    let _ = sock.send_to(&ok, from);
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        seen
    });
    (addr, handle)
}

/// Every user's per-user counter runs 1, 2, 3… over its calls, and the
/// global counter runs 1..=n over all calls in order.
fn assert_counters_are_consistent(calls: &[CounterCall]) {
    let runs: Vec<u32> = calls.iter().map(|c| c.per_run).collect();
    let expected: Vec<u32> = (1..=u32::try_from(calls.len()).expect("small")).collect();
    assert_eq!(runs, expected, "global counter in call order: {calls:?}");
    let mut per_user: HashMap<&str, Vec<u32>> = HashMap::new();
    for c in calls {
        per_user
            .entry(c.user.as_str())
            .or_default()
            .push(c.per_user);
    }
    for (user, counts) in &per_user {
        let expected: Vec<u32> = (1..=u32::try_from(counts.len()).expect("small")).collect();
        assert_eq!(
            counts, &expected,
            "user {user}'s counter across its calls: {calls:?}"
        );
    }
}

#[test]
fn user_variables_persist_across_a_users_calls() {
    // -users 2 -m 6: each user runs three calls. A <User> counter carries
    // from one call of a user to its next (1, 2, 3 per user), a <Global>
    // one across every call (1..6), and `-set region eu` seeds a global.
    let (addr, uas) = spawn_counter_uas(Duration::from_secs(4));
    let sc_path = std::env::temp_dir().join(format!("sipr-uservars-{}.xml", std::process::id()));
    std::fs::write(&sc_path, counter_uac_scenario()).expect("write scenario");
    let out = run_sipr(&[
        "-sf",
        sc_path.to_str().expect("utf8"),
        "-users",
        "2",
        "-m",
        "6",
        "-d",
        "20",
        "-set",
        "region",
        "eu",
        "-timeout",
        "15",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&sc_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 6 failed 0"), "{err}");

    let calls = uas.join().expect("uas thread");
    assert_eq!(calls.len(), 6, "{calls:?}");
    assert_counters_are_consistent(&calls);
    let users: Vec<&str> = calls.iter().map(|c| c.user.as_str()).collect();
    // SIPp hands out the free ids from the back of the pool: user 2 first.
    assert_eq!(&users[..2], ["2", "1"], "{calls:?}");
    assert_eq!(users.iter().filter(|u| **u == "1").count(), 3, "{calls:?}");
    assert!(
        calls.iter().all(|c| c.region == "eu"),
        "-set seeds the global: {calls:?}"
    );
}

#[test]
fn set_users_retires_and_reuses_ids_like_sipp() {
    // -users 3, then `set users 1` while all three calls are up: the first
    // call to end retires its id (more calls live than allowed), the other
    // two return to the free pool (SIPp free_user). `set users 3` later
    // takes the retired id back — with its counter — and creates one fresh
    // id for the remaining slot, so four ids appear in all; nothing is
    // dropped by number. `dump variables` lists the scopes meanwhile.
    let (addr, uas) = spawn_counter_uas(Duration::from_secs(5));
    let dir = std::env::temp_dir().join(format!("sipr-retire-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sc_path = dir.join("counters.xml");
    std::fs::write(&sc_path, counter_uac_scenario()).expect("write scenario");
    let cp = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .current_dir(&dir)
        .args([
            "-sf",
            sc_path.to_str().expect("utf8"),
            "-users",
            "3",
            "-m",
            "9",
            "-d",
            "1500",
            "-cp",
            &cp.to_string(),
            "-trace_err",
            "-timeout",
            "40",
            "-bg",
            &addr.to_string(),
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sipr");
    let mut stderr = child.stderr.take().expect("stderr");
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    let ctl = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let target = SocketAddr::from(([127, 0, 0, 1], cp));
    // All three calls are up (they pause 1.5 s before the BYE).
    std::thread::sleep(Duration::from_millis(600));
    ctl.send_to(b"cset users 1\n", target).expect("send");
    // ~3.2 s: the three initial calls are over, one replacement is running.
    std::thread::sleep(Duration::from_millis(2600));
    ctl.send_to(b"cset users 3\n", target).expect("send");
    ctl.send_to(b"cdump variables\n", target).expect("send");
    let code = wait_exit(&mut child, Duration::from_secs(30));
    let err = reader.join().expect("stderr");
    assert_eq!(code, Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 9 failed 0"), "{err}");

    let calls = uas.join().expect("uas thread");
    assert_eq!(calls.len(), 9, "{calls:?}");
    assert_counters_are_consistent(&calls);
    let users: Vec<&str> = calls.iter().map(|c| c.user.as_str()).collect();
    assert_eq!(&users[..3], ["3", "2", "1"], "SIPp's pool order: {calls:?}");
    let mut distinct = users.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct,
        ["1", "2", "3", "4"],
        "one fresh id after the regrow: {calls:?}"
    );
    // User 3's call ended first while three were live against a target of
    // one: retired, then reactivated by the regrow with its counter intact.
    assert!(
        users.iter().filter(|u| **u == "3").count() >= 2,
        "the retired id returns: {calls:?}"
    );

    let errors_log = std::fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().ends_with("_errors.log"))
        .map(|e| std::fs::read_to_string(e.path()).expect("read log"))
        .expect("an errors log");
    assert!(
        errors_log.contains("2 level 0 variables:\nper_run\nregion\n1 level 1 variables:\nper_user\n0 level 2 variables:\n"),
        "dump variables output:\n{errors_log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- manual transactions (M36) --------------------------------------------

/// Two INVITEs in flight at once, each naming its transaction; the 200s are
/// received by name — `second` first — and each ACK names its transaction.
fn overlapping_invites_scenario() -> String {
    let invite = |cseq: u32, txn: &str| {
        format!(
            r#"  <send retrans="500" start_txn="{txn}"><![CDATA[
    INVITE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: {cseq} INVITE
    Contact: <sip:sipr@[local_ip]:[local_port]>
    X-Txn: {txn}
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
"#
        )
    };
    let ack = |cseq: u32, txn: &str| {
        format!(
            r#"  <recv response="200" response_txn="{txn}"/>
  <send ack_txn="{txn}"><![CDATA[
    ACK sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: {cseq} ACK
    Content-Length: 0

  ]]></send>
"#
        )
    };
    format!(
        r#"<scenario name="overlap">
{}{}{}{}  <send retrans="500"><![CDATA[
    BYE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 3 BYE
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#,
        invite(1, "first"),
        invite(2, "second"),
        ack(2, "second"),
        ack(1, "first"),
    )
}

/// A UAS for [`overlapping_invites_scenario`]: once both INVITEs are in, it
/// answers them 200 in `answer_order` (by `X-Txn`) and records the CSeq
/// number of every ACK, in arrival order.
fn spawn_overlap_uas(
    answer_order: [&'static str; 2],
    idle: Duration,
) -> (SocketAddr, std::thread::JoinHandle<Vec<u32>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(idle)).expect("timeout");
    let handle = std::thread::spawn(move || {
        let mut invites: Vec<(String, Vec<u8>)> = Vec::new(); // (txn, 200)
        let mut answered = false;
        let mut acks = Vec::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let txn = msg.header("X-Txn").unwrap_or_default().trim().to_owned();
                    if invites.iter().all(|(t, _)| *t != txn) {
                        invites.push((txn, mirror_response(&msg, "200 OK", true)));
                    }
                    if invites.len() == 2 && !answered {
                        answered = true;
                        for want in answer_order {
                            if let Some((_, ok)) = invites.iter().find(|(t, _)| t == want) {
                                let _ = sock.send_to(ok, from);
                                std::thread::sleep(Duration::from_millis(50));
                            }
                        }
                    }
                }
                Some("ACK") => {
                    if let Some((n, _)) = msg.cseq() {
                        acks.push(n);
                    }
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        acks
    });
    (addr, handle)
}

#[test]
fn response_txn_matches_the_right_invite_of_two_overlapping_ones() {
    let sc_path = std::env::temp_dir().join(format!("sipr-overlap-{}.xml", std::process::id()));
    std::fs::write(&sc_path, overlapping_invites_scenario()).expect("write scenario");

    // The peer answers `second` first, as the scenario expects: each 200 is
    // taken by the recv naming its transaction (same code, same CSeq
    // method — only the branch tells them apart) and each ACK follows.
    let (addr, uas) = spawn_overlap_uas(["second", "first"], Duration::from_secs(3));
    let out = run_sipr(&[
        "-sf",
        sc_path.to_str().expect("utf8"),
        "-m",
        "1",
        "-d",
        "20",
        "-timeout",
        "10",
        "-bg",
        &addr.to_string(),
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    let acks = uas.join().expect("uas thread");
    assert_eq!(
        acks,
        [2, 1],
        "ACK for `second` (CSeq 2) first, then `first`"
    );

    // The other order: the 200 for `first` arrives while the scenario
    // waits for `second`'s. Nothing accepts a response of another
    // transaction, so the call fails on it — SIPp's rule ("matches only
    // responses to the message sent with start_txn").
    let (addr, uas) = spawn_overlap_uas(["first", "second"], Duration::from_secs(3));
    let out = run_sipr(&[
        "-sf",
        sc_path.to_str().expect("utf8"),
        "-m",
        "1",
        "-d",
        "20",
        "-timeout",
        "10",
        "-bg",
        &addr.to_string(),
    ]);
    let _ = std::fs::remove_file(&sc_path);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("successful 0 failed 1"), "{err}");
    assert!(err.contains("unexpected"), "{err}");
    let acks = uas.join().expect("uas thread");
    assert!(acks.is_empty(), "no transaction was acknowledged: {acks:?}");
}

/// INVITE `a` by name, then an INFO round trip, a pause and a BYE. The peer
/// sends a late 180 and a late copy of the INVITE's 200 during the pause.
fn late_final_scenario() -> String {
    r#"<scenario name="late-final">
  <send retrans="500" start_txn="a"><![CDATA[
    INVITE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: <sip:sipr@[local_ip]:[local_port]>
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="180" optional="true" response_txn="a"/>
  <recv response="200" response_txn="a"/>
  <send ack_txn="a"><![CDATA[
    ACK sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    Content-Length: 0

  ]]></send>
  <send retrans="500"><![CDATA[
    INFO sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 INFO
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <pause milliseconds="600"/>
  <send retrans="500"><![CDATA[
    BYE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 3 BYE
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
</scenario>"#
        .to_owned()
}

#[test]
fn late_final_response_to_a_named_invite_transaction_is_acked_again() {
    // After the INFO's 200 the peer sends the INVITE's 180 (late) and its
    // 200 again (as if the ACK were lost). Neither is a retransmission of
    // the last message received, so the generic dedupe does not apply:
    // the named transaction does — the 180 (which has an optional recv of
    // its own, as SIPp requires) is ignored, the 200 gets the ACK again,
    // and the call goes on to its BYE.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind uas");
    let addr = sock.local_addr().expect("addr");
    sock.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let uas = std::thread::spawn(move || {
        let mut invite_ok: Option<Vec<u8>> = None;
        let mut invite_ringing: Option<Vec<u8>> = None;
        let mut acks = 0u32;
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            match msg.method() {
                Some("INVITE") => {
                    let ok = mirror_response(&msg, "200 OK", true);
                    invite_ringing = Some(mirror_response(&msg, "180 Ringing", true));
                    let _ = sock.send_to(&ok, from);
                    invite_ok = Some(ok);
                }
                Some("ACK") => acks += 1,
                Some("INFO") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                    std::thread::sleep(Duration::from_millis(100));
                    if let Some(ringing) = &invite_ringing {
                        let _ = sock.send_to(ringing, from);
                    }
                    if let Some(ok) = &invite_ok {
                        let _ = sock.send_to(ok, from);
                    }
                }
                Some("BYE") => {
                    let _ = sock.send_to(&mirror_response(&msg, "200 OK", false), from);
                }
                _ => {}
            }
        }
        acks
    });

    let dir = std::env::temp_dir().join(format!("sipr-late-final-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sc_path = dir.join("late-final.xml");
    std::fs::write(&sc_path, late_final_scenario()).expect("write scenario");
    let out = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .current_dir(&dir)
        .args([
            "-sf",
            sc_path.to_str().expect("utf8"),
            "-m",
            "1",
            "-trace_err",
            "-timeout",
            "10",
            "-bg",
            &addr.to_string(),
        ])
        .output()
        .expect("run sipr");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr:\n{err}");
    assert!(err.contains("successful 1 failed 0"), "{err}");
    let acks = uas.join().expect("uas thread");
    assert_eq!(acks, 2, "the ACK was sent again for the late 200");
    let errors_log = std::fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().ends_with("_errors.log"))
        .map(|e| std::fs::read_to_string(e.path()).expect("read log"))
        .expect("an errors log");
    assert!(
        errors_log.contains("Ignoring provisional UDP message for transaction a"),
        "{errors_log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- exec command= and setdest (M37) ---------------------------------------

/// A UAS scenario that runs a shell command for every INVITE it answers.
/// The From value is quoted: it holds `<`, `>` and `;`, which a shell
/// would read as redirections and a command break (SIPp's docs show the
/// unquoted form, which fails the same way under sipp).
fn exec_uas_scenario() -> String {
    r#"<scenario name="exec-uas">
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
</scenario>"#
        .to_owned()
}

/// Zombie children of `pid` right now (`ps`: state `Z`).
#[cfg(unix)]
fn zombie_children_of(pid: u32) -> usize {
    let out = Command::new("ps")
        .args(["-A", "-o", "ppid=,stat="])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| {
            let mut parts = l.split_whitespace();
            parts.next() == Some(&pid.to_string())
                && parts.next().is_some_and(|st| st.starts_with('Z'))
        })
        .count()
}

#[test]
#[cfg(unix)] // the scenario's command is sh syntax and the zombie check uses ps
fn exec_command_runs_a_shell_per_matching_message() {
    // Three calls into a sipr UAS whose INVITE recv runs `echo … >> file`:
    // the file gets one From line per call, the command's shell runs with
    // sipr's cwd, and the runner reaps its children as it goes (no zombie
    // is ever seen hanging off the UAS while it runs).
    let dir = std::env::temp_dir().join(format!("sipr-exec-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sc_path = dir.join("exec-uas.xml");
    std::fs::write(&sc_path, exec_uas_scenario()).expect("write scenario");
    let port = free_port();
    let mut uas = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .current_dir(&dir)
        .args([
            "-sf",
            sc_path.to_str().expect("utf8"),
            "-i",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "3",
            "-timeout",
            "20",
            "-bg",
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn uas");
    let uas_pid = uas.id();
    std::thread::sleep(Duration::from_millis(300));
    let mut uac = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .args([
            "-sn",
            "uac",
            "-i",
            "127.0.0.1",
            "-r",
            "2",
            "-m",
            "3",
            "-d",
            "100",
            "-timeout",
            "15",
            "-bg",
            &format!("127.0.0.1:{port}"),
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn uac");
    let uac_code = wait_exit(&mut uac, Duration::from_secs(20));
    assert_eq!(uac_code, Some(0), "uac");
    // Every echo has long exited; the runner reaps within 100 ms.
    std::thread::sleep(Duration::from_millis(400));
    let zombies = zombie_children_of(uas_pid);
    let uas_code = wait_exit(&mut uas, Duration::from_secs(20));
    assert_eq!(uas_code, Some(0), "uas");
    assert_eq!(zombies, 0, "the exec runner reaps its children");
    let log = std::fs::read_to_string(dir.join("from_list.log")).expect("from_list.log");
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 3, "{log}");
    assert!(
        lines
            .iter()
            .all(|l| l.starts_with("From: ") && l.contains("<sip:sipr@127.0.0.1:")),
        "{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// INVITE/200/ACK to the peer, then `setdest` to the host and port the 200's
/// Contact named, then BYE there. Every request reports what
/// `[remote_ip]:[remote_port]` render.
fn setdest_uac_scenario(protocol: &str) -> String {
    format!(
        r#"<scenario name="setdest">
  <send retrans="500"><![CDATA[
    INVITE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: <sip:sipr@[local_ip]:[local_port];transport=[transport]>
    X-Remote: [remote_ip]:[remote_port]
    Max-Forwards: 70
    Content-Length: 0

  ]]></send>
  <recv response="180" optional="true"/>
  <recv response="200" rrs="true"/>
  <send><![CDATA[
    ACK sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 1 ACK
    X-Remote: [remote_ip]:[remote_port]
    Content-Length: 0

  ]]></send>
  <nop>
    <action>
      <assignstr assign_to="url" value="[next_url]"/>
      <log message="setdest: url=[$url] next_url=[next_url]"/>
      <ereg regexp="sip:.*@([0-9.]+):([0-9]+)" search_in="var" variable="url"
            check_it="true" assign_to="dummy,host,port"/>
      <setdest host="[$host]" port="[$port]" protocol="{protocol}"/>
    </action>
  </nop>
  <send retrans="500"><![CDATA[
    BYE sip:svc@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
    From: <sip:sipr@[local_ip]:[local_port]>;tag=[pid]t[call_number]
    To: <sip:svc@[remote_ip]:[remote_port]>[peer_tag_param]
    Call-ID: [call_id]
    CSeq: 2 BYE
    X-Remote: [remote_ip]:[remote_port]
    Content-Length: 0

  ]]></send>
  <recv response="200"/>
  <Reference variables="dummy"/>
</scenario>"#
    )
}

/// Run sipr on `scenario` from a fresh temp dir with `-trace_err`; returns
/// the output and the error trace (for assertion messages).
fn run_sipr_traced(tag: &str, scenario: &str, args: &[&str]) -> (std::process::Output, String) {
    let dir = std::env::temp_dir().join(format!("sipr-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sc_path = dir.join("scenario.xml");
    std::fs::write(&sc_path, scenario).expect("write scenario");
    let out = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .current_dir(&dir)
        .arg("-sf")
        .arg(&sc_path)
        .arg("-trace_err")
        .args(args)
        .output()
        .expect("run sipr");
    let errors_log = std::fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().ends_with("_errors.log"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    (out, errors_log)
}

/// `mirror_response` with its Contact replaced by one naming `contact_port`
/// (the redirect the scenario follows).
fn ok_with_contact(msg: &Inbound, contact_port: u16) -> Vec<u8> {
    let ok = String::from_utf8(mirror_response(msg, "200 OK", true)).expect("utf8");
    let (headers, body) = ok.split_once("\r\n\r\n").expect("header end");
    let mut out: Vec<String> = headers
        .split("\r\n")
        .filter(|l| !l.to_ascii_lowercase().starts_with("contact:"))
        .map(ToOwned::to_owned)
        .collect();
    out.push(format!("Contact: <sip:svc@127.0.0.1:{contact_port}>"));
    format!("{}\r\n\r\n{body}", out.join("\r\n")).into_bytes()
}

/// What a socket saw: `(method, X-Remote)` per request, in order.
type Seen = Vec<(String, String)>;

fn seen_entry(msg: &Inbound) -> (String, String) {
    (
        msg.method().unwrap_or_default().to_owned(),
        msg.header("X-Remote").unwrap_or_default().trim().to_owned(),
    )
}

#[test]
fn setdest_redirects_the_rest_of_the_call_over_udp() {
    // Socket 1 answers the INVITE with a Contact on socket 2; after the ACK
    // the scenario `setdest`s there, so the BYE lands on socket 2 — while
    // `[remote_ip]:[remote_port]` in it still name socket 1 (SIPp's
    // globals are untouched by setdest).
    let sock2 = UdpSocket::bind("127.0.0.1:0").expect("bind 2");
    let port2 = sock2.local_addr().expect("addr").port();
    sock2
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let second = std::thread::spawn(move || {
        let mut seen: Seen = Vec::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock2.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            seen.push(seen_entry(&msg));
            if msg.method() == Some("BYE") {
                let _ = sock2.send_to(&mirror_response(&msg, "200 OK", false), from);
            }
        }
        seen
    });
    let sock1 = UdpSocket::bind("127.0.0.1:0").expect("bind 1");
    let addr1 = sock1.local_addr().expect("addr");
    sock1
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let first = std::thread::spawn(move || {
        let mut seen: Seen = Vec::new();
        let mut buf = [0u8; 65_535];
        while let Ok((n, from)) = sock1.recv_from(&mut buf) {
            let Ok(msg) = Inbound::parse(&buf[..n]) else {
                continue;
            };
            seen.push(seen_entry(&msg));
            if msg.method() == Some("INVITE") {
                let _ = sock1.send_to(&ok_with_contact(&msg, port2), from);
            }
        }
        seen
    });
    let (out, errors_log) = run_sipr_traced(
        "setdest-udp",
        &setdest_uac_scenario("udp"),
        &["-m", "1", "-timeout", "10", "-bg", &addr1.to_string()],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{err}\nerrors:\n{errors_log}"
    );
    assert!(err.contains("successful 1 failed 0"), "{err}");
    let nominal = addr1.to_string();
    let on_first = first.join().expect("first");
    let on_second = second.join().expect("second");
    assert_eq!(
        on_first,
        [
            ("INVITE".to_owned(), nominal.clone()),
            ("ACK".to_owned(), nominal.clone())
        ],
        "socket 1"
    );
    assert_eq!(
        on_second,
        [("BYE".to_owned(), nominal)],
        "socket 2: redirected BYE, keywords unchanged"
    );
}

/// A TCP listener that answers like the UDP sockets above: accepts one
/// connection, replies 200 (with `contact_port` in the Contact) to an
/// INVITE and 200 to a BYE, and records `(method, X-Remote)`.
fn spawn_setdest_tcp_listener(
    contact_port: Option<u16>,
    idle: Duration,
) -> (SocketAddr, std::thread::JoinHandle<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let addr = listener.local_addr().expect("addr");
    listener.set_nonblocking(false).expect("blocking");
    let handle = std::thread::spawn(move || {
        let mut seen: Seen = Vec::new();
        let Ok((mut stream, _)) = listener.accept() else {
            return seen;
        };
        stream.set_read_timeout(Some(idle)).ok();
        let mut framer = TcpFramer::new();
        let mut buf = [0u8; 16_384];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    framer.push(&buf[..n]);
                    while let Some(raw) = framer.next_message() {
                        let Ok(msg) = Inbound::parse(&raw) else {
                            continue;
                        };
                        seen.push(seen_entry(&msg));
                        match msg.method() {
                            Some("INVITE") => {
                                let ok = contact_port.map_or_else(
                                    || mirror_response(&msg, "200 OK", true),
                                    |p| ok_with_contact(&msg, p),
                                );
                                let _ = stream.write_all(&ok);
                            }
                            Some("BYE") => {
                                let _ = stream.write_all(&mirror_response(&msg, "200 OK", false));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        seen
    });
    (addr, handle)
}

#[test]
fn setdest_over_per_call_tcp_reconnects_to_the_new_peer() {
    // `-t tn`: the call's own connection is closed and re-dialled to the
    // Contact's host and port; the BYE arrives on the second listener.
    let (addr2, second) = spawn_setdest_tcp_listener(None, Duration::from_secs(3));
    let (addr1, first) = spawn_setdest_tcp_listener(Some(addr2.port()), Duration::from_secs(3));
    let (out, errors_log) = run_sipr_traced(
        "setdest-tcp",
        &setdest_uac_scenario("tcp"),
        &[
            "-t",
            "tn",
            "-m",
            "1",
            "-timeout",
            "10",
            "-bg",
            &addr1.to_string(),
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr:\n{err}\nerrors:\n{errors_log}"
    );
    assert!(err.contains("successful 1 failed 0"), "{err}");
    let nominal = addr1.to_string();
    let methods = |seen: &Seen| seen.iter().map(|(m, _)| m.clone()).collect::<Vec<_>>();
    let on_first = first.join().expect("first");
    let on_second = second.join().expect("second");
    assert_eq!(methods(&on_first), ["INVITE", "ACK"], "{on_first:?}");
    assert_eq!(on_second, [("BYE".to_owned(), nominal)], "{on_second:?}");
}

#[test]
fn setdest_is_refused_where_sipp_refuses_it() {
    // Mono TCP (`-t t1`): SIPp aborts the whole run with "Changing
    // destinations for TCP or SCTP requires multisocket mode."; sipr fails
    // that call with the same words and keeps running.
    let (addr, _uas) = spawn_setdest_tcp_listener(Some(5090), Duration::from_secs(3));
    let dir = std::env::temp_dir().join(format!("sipr-setdest-refused-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sc_path = dir.join("setdest.xml");
    std::fs::write(&sc_path, setdest_uac_scenario("tcp")).expect("write scenario");
    let out = Command::new(env!("CARGO_BIN_EXE_sipr"))
        .current_dir(&dir)
        .args([
            "-sf",
            sc_path.to_str().expect("utf8"),
            "-t",
            "t1",
            "-m",
            "1",
            "-trace_err",
            "-timeout",
            "10",
            "-bg",
            &addr.to_string(),
        ])
        .output()
        .expect("run sipr");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "one failed call: {err}");
    assert!(err.contains("successful 0 failed 1"), "{err}");
    let errors_log = std::fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().ends_with("_errors.log"))
        .map(|e| std::fs::read_to_string(e.path()).expect("read log"))
        .expect("an errors log");
    assert!(
        errors_log
            .contains("setdest: Changing destinations for TCP or SCTP requires multisocket mode."),
        "{errors_log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
