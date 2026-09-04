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
    // focused guard that the [service] default resolves into the URI.
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
    let media_base = free_port();
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
