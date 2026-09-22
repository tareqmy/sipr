//! The HTTP/JSON control API (`docs/CONTROL_API.md`), routed onto the
//! engine through a [`ControlLink`].
//!
//! | Method | Path        | Effect |
//! |--------|-------------|--------|
//! | GET    | `/health`   | `{"status":"ok","version":...}` |
//! | GET    | `/stats`    | the latest statistics snapshot |
//! | GET    | `/metrics`  | the same snapshot in Prometheus text format |
//! | GET    | `/control`  | rate / pause / users / limit / quit state |
//! | POST   | `/control`  | partial update: `rate`, `rate_scale`, `paused`, `users`, `limit` |
//! | POST   | `/quit`     | `{"force":bool}` — drain (default) or abort |
//! | POST   | `/command`  | `{"command":"set rate 10"}` — SIPp's control-socket line |
//! | GET    | `/scenario` | name, role, and the compiled steps |
//!
//! Every error is `{"error":"..."}` with a 4xx/5xx status; control errors
//! carry SIPp's own warning text. A bearer token, when configured, is
//! required on every path but `/health`.

use std::sync::Arc;
use std::sync::mpsc::channel;
use std::time::Duration;

use sipr_stats::Snapshot;

use crate::http::{Handler, Request, Response};
use crate::json::{self, Json, num, num_u64, object, text};
use crate::{ControlCmd, ControlLink, ControlRequest, ControlState};

/// How long a request waits for the engine to answer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the request handler for `link`, gated by `token` when set.
#[must_use]
pub fn handler(link: ControlLink, token: Option<String>) -> Handler {
    Arc::new(move |req: &Request| route(&link, token.as_deref(), req))
}

fn route(link: &ControlLink, token: Option<&str>, req: &Request) -> Response {
    if req.path != "/health"
        && let Some(t) = token
        && !authorized(req, t)
    {
        return error(401, "unauthorized");
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/health") => Response::json(
            200,
            object([("status", text("ok")), ("version", text(link.version))]).to_string(),
        ),
        ("GET", "/stats") => {
            let snap = link.snapshot.lock().map(|s| s.clone()).unwrap_or_default();
            Response::json(200, snapshot_json(&snap).to_string())
        }
        ("GET", "/metrics") => {
            let snap = link.snapshot.lock().map(|s| s.clone()).unwrap_or_default();
            Response::prometheus(200, crate::prometheus::render(&snap))
        }
        ("GET", "/control") => reply(ask(link, ControlCmd::Query)),
        ("POST", "/control") => match parse_body(req) {
            Err(e) => error(400, &e),
            Ok(body) => apply_control(link, &body),
        },
        ("POST", "/quit") => {
            let force = parse_body(req)
                .ok()
                .and_then(|b| b.get("force").and_then(Json::as_bool))
                .unwrap_or(false);
            match ask(link, ControlCmd::Quit { force }) {
                Ok(state) => Response::json(202, state_json(&state).to_string()),
                Err(e) => error(409, &e),
            }
        }
        ("POST", "/command") => match parse_body(req)
            .and_then(|b| {
                b.get("command")
                    .and_then(Json::as_str)
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| "body needs a \"command\" string".to_owned())
            })
            .and_then(|line| crate::parse_command(&line))
        {
            Err(e) => error(400, &e),
            Ok(cmd) => reply(ask(link, cmd)),
        },
        ("GET", "/scenario") => Response::json(
            200,
            object([
                ("name", text(link.scenario_name.clone())),
                ("role", text(link.role)),
                (
                    "steps",
                    Json::Array(link.steps.iter().map(|s| text(s.clone())).collect()),
                ),
            ])
            .to_string(),
        ),
        (
            _,
            "/health" | "/stats" | "/metrics" | "/control" | "/quit" | "/command" | "/scenario",
        ) => error(405, "method not allowed"),
        _ => error(404, "no such endpoint"),
    }
}

fn authorized(req: &Request, token: &str) -> bool {
    let presented = req
        .header("Authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        .map(ToOwned::to_owned)
        .or_else(|| req.query_param("token"));
    presented.is_some_and(|p| constant_time_eq(p.as_bytes(), token.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn parse_body(req: &Request) -> Result<Json, String> {
    if req.body.is_empty() {
        return Ok(Json::Object(Default::default()));
    }
    let text = std::str::from_utf8(&req.body).map_err(|_| "body is not UTF-8".to_owned())?;
    json::parse(text).map_err(|e| format!("invalid JSON: {e}"))
}

/// `POST /control`: apply each present field in turn (rate_scale first so
/// a rate in the same request is not scaled twice), then report state.
fn apply_control(link: &ControlLink, body: &Json) -> Response {
    let mut cmds = Vec::new();
    if let Some(v) = body.get("rate_scale").and_then(Json::as_f64) {
        cmds.push(ControlCmd::SetRateScale(v));
    }
    if let Some(v) = body.get("rate").and_then(Json::as_f64) {
        cmds.push(ControlCmd::SetRate(v));
    }
    if let Some(v) = body.get("users").and_then(Json::as_f64) {
        cmds.push(ControlCmd::SetUsers(as_count(v)));
    }
    if let Some(v) = body.get("limit").and_then(Json::as_f64) {
        cmds.push(ControlCmd::SetLimit(as_count(v)));
    }
    if let Some(v) = body.get("paused").and_then(Json::as_bool) {
        cmds.push(ControlCmd::SetPaused(v));
    }
    if cmds.is_empty() {
        return error(
            400,
            "nothing to set: give rate, rate_scale, paused, users, or limit",
        );
    }
    let mut last = Err("no command".to_owned());
    for cmd in cmds {
        last = ask(link, cmd);
        if last.is_err() {
            break;
        }
    }
    reply(last)
}

fn as_count(v: f64) -> u64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        v.max(0.0).round() as u64
    }
}

/// Send a command and wait for the engine's answer.
fn ask(link: &ControlLink, cmd: ControlCmd) -> Result<ControlState, String> {
    let (tx, rx) = channel();
    link.requests
        .send(ControlRequest {
            cmd,
            reply: Some(tx),
        })
        .map_err(|_| "engine has stopped".to_owned())?;
    rx.recv_timeout(REPLY_TIMEOUT)
        .map_err(|_| "engine did not answer".to_owned())?
}

fn reply(result: Result<ControlState, String>) -> Response {
    match result {
        Ok(state) => Response::json(200, state_json(&state).to_string()),
        Err(e) => error(400, &e),
    }
}

fn error(status: u16, message: &str) -> Response {
    Response::json(status, object([("error", text(message))]).to_string())
}

/// The control state as JSON.
#[must_use]
pub fn state_json(s: &ControlState) -> Json {
    object([
        ("rate", num(s.rate)),
        ("rate_scale", num(s.rate_scale)),
        ("paused", Json::Bool(s.paused)),
        ("users", s.users.map_or(Json::Null, num_u64)),
        ("limit", s.limit.map_or(Json::Null, num_u64)),
        ("quitting", text(s.quitting.as_str())),
    ])
}

/// The statistics snapshot as JSON. Field names follow SIPp's counters
/// and the CSV; durations carry a `_ms` suffix.
#[must_use]
pub fn snapshot_json(s: &Snapshot) -> Json {
    let rtds = s
        .rtds
        .iter()
        .map(|r| {
            object([
                ("name", text(r.name.clone())),
                ("count", num_u64(r.count)),
                ("mean_ms", num(r.mean_ms)),
                ("stddev_ms", num(r.stddev_ms)),
                ("p99_ms", num_u64(r.p99_ms)),
                ("max_ms", num_u64(r.max_ms)),
            ])
        })
        .collect();
    let rows = |rows: &[(String, u64)]| {
        Json::Array(
            rows.iter()
                .map(|(label, count)| {
                    object([("label", text(label.clone())), ("count", num_u64(*count))])
                })
                .collect(),
        )
    };
    let steps = s
        .steps
        .iter()
        .map(|st| {
            object([
                ("label", text(st.label.clone())),
                ("hidden", Json::Bool(st.hidden)),
                ("sent", num_u64(st.stats.sent)),
                ("recv", num_u64(st.stats.recv)),
                ("retrans", num_u64(st.stats.retrans)),
                ("timeouts", num_u64(st.stats.timeouts)),
                ("unexpected", num_u64(st.stats.unexpected)),
            ])
        })
        .collect();
    object([
        ("scenario", text(s.scenario.clone())),
        ("role", text(if s.uas { "UAS" } else { "UAC" })),
        (
            "elapsed_ms",
            num_u64(u64::try_from(s.elapsed.as_millis()).unwrap_or(u64::MAX)),
        ),
        ("live", num_u64(u64::try_from(s.live).unwrap_or(u64::MAX))),
        ("rate_target", num(s.rate_target)),
        ("rate_period_cps", num(s.rate_period)),
        ("rate_cumulative_cps", num(s.rate_cumulative)),
        ("paused", Json::Bool(s.paused)),
        ("hide", Json::Bool(s.hide)),
        ("display", text(s.display.label())),
        ("mixed", Json::Bool(s.mixed)),
        ("created", num_u64(s.created)),
        ("successful", num_u64(s.successful)),
        ("failed", num_u64(s.failed)),
        ("failed_unexpected", num_u64(s.failed_unexpected)),
        ("failed_timeout", num_u64(s.failed_timeout)),
        ("failed_retrans", num_u64(s.failed_retrans)),
        ("failed_other", num_u64(s.failed_other)),
        ("messages_sent", num_u64(s.messages_sent)),
        ("messages_matched", num_u64(s.messages_matched)),
        ("retrans_sent", num_u64(s.retrans_sent)),
        ("retrans_recv", num_u64(s.retrans_recv)),
        ("auto_answered", num_u64(s.auto_answered)),
        ("unexpected", num_u64(s.unexpected)),
        ("garbage", num_u64(s.garbage)),
        ("rtp_streams_started", num_u64(s.rtp_streams_started)),
        ("rtp_packets_sent", num_u64(s.rtp_packets_sent)),
        ("rtp_bytes_sent", num_u64(s.rtp_bytes_sent)),
        ("rtp_bytes_received", num_u64(s.rtp_bytes_received)),
        ("rtp_echo_packets", num_u64(s.rtp_echo_packets)),
        ("rtp_echo2_packets", num_u64(s.rtp_echo2_packets)),
        ("rtp_check_ok", num_u64(s.rtp_check_ok)),
        ("rtp_check_failed", num_u64(s.rtp_check_failed)),
        ("rtd", Json::Array(rtds)),
        (
            "call_length",
            object([
                ("count", num_u64(s.call_length.0)),
                ("mean_ms", num(s.call_length.1)),
                ("max_ms", num_u64(s.call_length.2)),
            ]),
        ),
        ("response_time_repartition", rows(&s.response_rows)),
        ("call_length_repartition", rows(&s.call_length_rows)),
        ("steps", Json::Array(steps)),
    ])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::Quitting;
    use crate::http::HttpServer;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Mutex;

    /// A fake engine: answers every request with a fixed state, recording
    /// the commands it saw.
    fn fake_engine() -> (ControlLink, std::sync::mpsc::Receiver<ControlCmd>) {
        let (req_tx, req_rx) = channel::<ControlRequest>();
        let (seen_tx, seen_rx) = channel::<ControlCmd>();
        std::thread::spawn(move || {
            while let Ok(r) = req_rx.recv() {
                let outcome = match &r.cmd {
                    ControlCmd::SetRate(_) if false => unreachable!(),
                    ControlCmd::SetUsers(_) => Err(
                        "Users can not be changed at run time for a rate-based benchmark."
                            .to_owned(),
                    ),
                    _ => Ok(ControlState {
                        rate: 10.0,
                        rate_scale: 1.0,
                        paused: false,
                        users: None,
                        limit: Some(3),
                        quitting: Quitting::No,
                    }),
                };
                let _ = seen_tx.send(r.cmd.clone());
                if let Some(reply) = r.reply {
                    let _ = reply.send(outcome);
                }
            }
        });
        let snap = Snapshot {
            scenario: "t".into(),
            created: 7,
            ..Default::default()
        };
        (
            ControlLink {
                requests: req_tx,
                snapshot: Arc::new(Mutex::new(snap)),
                scenario_name: "t".into(),
                role: "UAC",
                steps: vec!["send INVITE".into()],
                version: "0.0-test",
            },
            seen_rx,
        )
    }

    fn call(addr: std::net::SocketAddr, raw: &str) -> (u16, Json) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let status: u16 = out[9..12].parse().unwrap();
        let body = out.split("\r\n\r\n").nth(1).unwrap_or("null");
        (status, json::parse(body).unwrap())
    }

    /// `/metrics` answers Prometheus text, not JSON, and honours the token
    /// like every other path but `/health`.
    #[test]
    fn metrics_endpoint_serves_prometheus_text() {
        let (link, _seen) = fake_engine();
        let server = HttpServer::start(
            "127.0.0.1:0".parse().unwrap(),
            handler(link, Some("s3cret".into())),
        )
        .unwrap();
        let a = server.local_addr();
        let mut sock = TcpStream::connect(a).unwrap();
        sock.write_all(b"GET /metrics?token=s3cret HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut out = String::new();
        sock.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
        assert!(
            out.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"),
            "scrapers pick the parser from this header:\n{out}"
        );
        let body = out.split("\r\n\r\n").nth(1).unwrap_or_default();
        assert!(
            body.contains("# TYPE sipr_calls_created_total counter"),
            "{body}"
        );
        assert!(body.contains("sipr_calls_created_total 7"), "{body}");

        // No token: refused, like the other guarded paths.
        let (st, _) = call(a, "GET /metrics HTTP/1.1\r\n\r\n");
        assert_eq!(st, 401);
    }

    #[test]
    fn endpoints_route_and_authenticate() {
        let (link, seen) = fake_engine();
        let server = HttpServer::start(
            "127.0.0.1:0".parse().unwrap(),
            handler(link, Some("s3cret".into())),
        )
        .unwrap();
        let a = server.local_addr();
        let (st, body) = call(a, "GET /health HTTP/1.1\r\n\r\n");
        assert_eq!(st, 200);
        assert_eq!(body.get("status").and_then(Json::as_str), Some("ok"));
        let (st, _) = call(a, "GET /stats HTTP/1.1\r\n\r\n");
        assert_eq!(st, 401, "token required");
        let (st, body) = call(a, "GET /stats?token=s3cret HTTP/1.1\r\n\r\n");
        assert_eq!(st, 200);
        assert_eq!(body.get("created").and_then(Json::as_f64), Some(7.0));
        assert_eq!(body.get("role").and_then(Json::as_str), Some("UAC"));
        let (st, body) = call(
            a,
            "POST /control HTTP/1.1\r\nAuthorization: Bearer s3cret\r\nContent-Length: 25\r\n\r\n{\"rate\":20,\"paused\":true}",
        );
        assert_eq!(st, 200, "{body:?}");
        assert_eq!(body.get("limit").and_then(Json::as_f64), Some(3.0));
        assert_eq!(seen.recv().unwrap(), ControlCmd::SetRate(20.0));
        assert_eq!(seen.recv().unwrap(), ControlCmd::SetPaused(true));
        let (st, body) = call(
            a,
            "POST /control HTTP/1.1\r\nAuthorization: Bearer s3cret\r\nContent-Length: 11\r\n\r\n{\"users\":5}",
        );
        assert_eq!(st, 400);
        assert!(
            body.get("error")
                .and_then(Json::as_str)
                .unwrap()
                .contains("Users can not")
        );
        let (st, body) = call(
            a,
            "POST /command HTTP/1.1\r\nAuthorization: Bearer s3cret\r\nContent-Length: 26\r\n\r\n{\"command\":\"set rate 5.5\"}",
        );
        assert_eq!(st, 200, "{body:?}");
        let _ = seen.recv().unwrap(); // SetUsers
        assert_eq!(seen.recv().unwrap(), ControlCmd::SetRate(5.5));
        let (st, body) = call(
            a,
            "POST /quit HTTP/1.1\r\nAuthorization: Bearer s3cret\r\nContent-Length: 14\r\n\r\n{\"force\":true}",
        );
        assert_eq!(st, 202, "{body:?}");
        assert_eq!(seen.recv().unwrap(), ControlCmd::Quit { force: true });
        let (st, body) = call(a, "GET /scenario?token=s3cret HTTP/1.1\r\n\r\n");
        assert_eq!(st, 200);
        assert_eq!(body.get("steps").unwrap().to_string(), "[\"send INVITE\"]");
        let (st, _) = call(a, "GET /nope?token=s3cret HTTP/1.1\r\n\r\n");
        assert_eq!(st, 404);
        let (st, _) = call(a, "DELETE /stats?token=s3cret HTTP/1.1\r\n\r\n");
        assert_eq!(st, 405);
        let (st, body) = call(
            a,
            "POST /control HTTP/1.1\r\nAuthorization: Bearer s3cret\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert_eq!(st, 400);
        assert!(body.get("error").is_some());
    }
}
