//! A deliberately small HTTP/1.1 server for the control API: one accept
//! thread, one short-lived thread per connection, `Connection: close`.
//! It parses a request head plus a `Content-Length` body and hands a
//! [`Request`] to a handler. No keep-alive, no chunking, no TLS — this is
//! a control plane on a loopback port, not a web server.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `GET`, `POST`, ...
    pub method: String,
    /// Path without the query string.
    pub path: String,
    /// The query string (without `?`), or empty.
    pub query: String,
    /// Header `(name lowercased, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Request {
    /// A header value by case-insensitive name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    /// A query parameter by name (no decoding beyond `+`).
    #[must_use]
    pub fn query_param(&self, key: &str) -> Option<String> {
        self.query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == key).then(|| v.replace('+', " "))
        })
    }
}

/// A response to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// `Content-Type`.
    pub content_type: &'static str,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// A JSON response.
    #[must_use]
    pub fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into_bytes(),
        }
    }

    /// A plain-text response.
    #[must_use]
    pub fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }
}

/// Request handler.
pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync>;

/// Largest accepted request (head + body).
const MAX_REQUEST: usize = 1 << 20;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The listening server; dropping it does not stop the accept thread (the
/// thread ends when the process does), which is fine for a control plane.
pub struct HttpServer {
    local_addr: SocketAddr,
}

impl HttpServer {
    /// Bind `addr` and serve `handler` on a background thread.
    ///
    /// # Errors
    ///
    /// The bind error.
    pub fn start(addr: SocketAddr, handler: Handler) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        std::thread::Builder::new()
            .name("sipr-http".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let handler = Arc::clone(&handler);
                    let _ = std::thread::Builder::new()
                        .name("sipr-http-conn".into())
                        .spawn(move || serve_connection(stream, &handler));
                }
            })?;
        Ok(Self { local_addr })
    }

    /// The bound address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

fn serve_connection(mut stream: TcpStream, handler: &Handler) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let response = match read_request(&mut stream) {
        Ok(req) => handler(&req),
        Err(status) => Response::text(status, "bad request\n"),
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\
         Cache-Control: no-store\r\n\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

/// Read one request; `Err(status)` for a malformed or oversized one.
fn read_request(stream: &mut TcpStream) -> Result<Request, u16> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() > MAX_REQUEST {
            return Err(431_u16);
        }
        let n = stream.read(&mut chunk).map_err(|_| 400_u16)?;
        if n == 0 {
            return Err(400_u16);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| 400_u16)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(400_u16)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(400_u16)?.to_owned();
    let target = parts.next().ok_or(400_u16)?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(400_u16)?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let content_length: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_REQUEST {
        return Err(413_u16);
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).map_err(|_| 400_u16)?;
        if n == 0 {
            return Err(400_u16);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok(Request {
        method,
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        body,
    })
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Send raw bytes and return the full response text.
    pub fn roundtrip(addr: SocketAddr, raw: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn serves_get_and_post_with_bodies() {
        let handler: Handler = Arc::new(|req: &Request| {
            let body = format!(
                "{} {} q={} auth={} body={}",
                req.method,
                req.path,
                req.query_param("a").unwrap_or_default(),
                req.header("Authorization").unwrap_or("-"),
                String::from_utf8_lossy(&req.body)
            );
            Response::text(200, &body)
        });
        let server = HttpServer::start("127.0.0.1:0".parse().unwrap(), handler).unwrap();
        let addr = server.local_addr();
        let out = roundtrip(
            addr,
            "GET /stats?a=1+2 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t\r\n\r\n",
        );
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
        assert!(
            out.ends_with("GET /stats q=1 2 auth=Bearer t body="),
            "{out}"
        );
        let out = roundtrip(
            addr,
            "POST /control HTTP/1.1\r\nContent-Length: 11\r\n\r\n{\"rate\":10}",
        );
        assert!(out.ends_with("body={\"rate\":10}"), "{out}");
        let out = roundtrip(addr, "garbage\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    }
}
