//! SIP over WebSocket (RFC 7118) for the TCP and TLS transports: the HTTP
//! upgrade handshake (RFC 6455 §4) and the frame codec (§5).
//!
//! WebSocket is a second *framing* of a stream connection, not a transport
//! of its own: [`Framing::WebSocket`] on a [`crate::TransportConfig`] makes
//! the TCP or TLS transport upgrade each connection and then carry one SIP
//! message per WebSocket message (RFC 7118 §5: the client sends text
//! frames; both sides accept text or binary, fragmented or not). sipr is the
//! WebSocket client on a connection it dialed and the server on one it
//! accepted, whatever its SIP role, and only the client masks (§5.3).
//!
//! A sipr addition: SIPp has no WebSocket transport, so the two RFCs are
//! the only oracle. Inbound tolerance follows the rest of the crate: a peer
//! that breaks the protocol loses its connection, never the run.

use std::io::{self, Read, Write};
use std::sync::{Mutex, MutexGuard};

use crate::rng::Rng;
use crate::tcp::TcpFramer;

/// How the bytes of a stream transport are cut into SIP messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Framing {
    /// SIP straight on the stream: `Content-Length` framing (RFC 3261 §7.5).
    #[default]
    Sip,
    /// SIP over WebSocket (RFC 7118): one SIP message per WebSocket message.
    WebSocket,
}

/// What sipr puts in the upgrade request it sends as the WebSocket client
/// (RFC 6455 §4.1): the resource name on the request line and an optional
/// `Origin` header, for servers that route or gate on them
/// (`--sipr-ws-path`, `--sipr-ws-origin`; M53). The default asks for `/`
/// and sends no `Origin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsRequest {
    path: String,
    origin: Option<String>,
}

impl Default for WsRequest {
    fn default() -> Self {
        Self {
            path: "/".to_owned(),
            origin: None,
        }
    }
}

impl WsRequest {
    /// A request for `path` (which must start with `/`), with an `Origin`
    /// header when `origin` is given.
    ///
    /// # Errors
    ///
    /// A path that does not start with `/`, an empty origin, or either
    /// holding whitespace or a control character (which would break the
    /// request head).
    pub fn new(path: &str, origin: Option<&str>) -> Result<Self, String> {
        if !path.starts_with('/') {
            return Err(format!("WebSocket path '{path}' must start with '/'"));
        }
        check_head_token("path", path)?;
        if let Some(o) = origin {
            if o.is_empty() {
                return Err("WebSocket origin must not be empty".to_owned());
            }
            check_head_token("origin", o)?;
        }
        Ok(Self {
            path: path.to_owned(),
            origin: origin.map(str::to_owned),
        })
    }

    /// The resource name on the request line.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The `Origin` header's value, if one is sent.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// Whether this is the default request (`/`, no `Origin`).
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.path == "/" && self.origin.is_none()
    }
}

/// A value that goes on a request line or header must not carry what
/// ends or splits one.
fn check_head_token(what: &str, value: &str) -> Result<(), String> {
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "WebSocket {what} '{value}' must not contain whitespace or control characters"
        ));
    }
    Ok(())
}

/// What the server side of the upgrade learned from the request, with the
/// bytes that arrived after its head (the start of the first frames).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUpgrade {
    /// The resource name the client asked for (`/` when absent).
    pub path: String,
    /// The client's `Origin` header, if any.
    pub origin: Option<String>,
    /// Bytes read past the request head.
    pub rest: Vec<u8>,
}

/// The constant every accept key is derived with (RFC 6455 §1.3).
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The largest WebSocket message accepted, fragments included. A SIP
/// message is a few kilobytes; a hostile 64-bit length must not allocate.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// The largest HTTP head read during the handshake.
const MAX_HEAD: usize = 16 * 1024;

/// The `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`
/// (RFC 6455 §4.2.2): base64 of the SHA-1 of the key and the GUID.
#[must_use]
pub fn accept_key(key: &str) -> String {
    let mut input = key.trim().as_bytes().to_vec();
    input.extend_from_slice(GUID.as_bytes());
    sipr_auth::base64::encode(&sipr_auth::sha1(&input))
}

/// Upgrade a freshly connected stream as the client (RFC 6455 §4.1, with
/// RFC 7118 §4's `Sec-WebSocket-Protocol: sip`), asking for `request`'s
/// path and `Origin`. Returns the bytes that arrived after the response
/// head: the start of the first frames.
///
/// # Errors
///
/// I/O failures, a response that is not `101`, or a wrong accept key.
pub fn client_handshake<S: Read + Write>(
    io: &mut S,
    host: &str,
    request: &WsRequest,
    rng: &mut Rng,
) -> io::Result<Vec<u8>> {
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce);
    let key = sipr_auth::base64::encode(&nonce);
    let origin = request
        .origin()
        .map(|o| format!("Origin: {o}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {host}\r\n\
         {origin}\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: sip\r\n\
         \r\n",
        request.path()
    );
    io.write_all(request.as_bytes())?;
    io.flush()?;
    let (head, rest) = read_head(io)?;
    let head = String::from_utf8_lossy(&head);
    let status = head.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 101") {
        return Err(io::Error::other(format!(
            "WebSocket upgrade refused: {status}"
        )));
    }
    match header(&head, "Sec-WebSocket-Accept") {
        Some(accept) if accept == accept_key(&key) => Ok(rest),
        Some(_) => Err(io::Error::other(
            "WebSocket upgrade: wrong Sec-WebSocket-Accept",
        )),
        None => Err(io::Error::other(
            "WebSocket upgrade: no Sec-WebSocket-Accept",
        )),
    }
}

/// Upgrade an accepted stream as the server (RFC 6455 §4.2): read the
/// request, answer `101` with the accept key, and echo the `sip`
/// subprotocol when the client offered it. Any path and any `Origin` are
/// accepted and reported; a test tool gates on neither.
///
/// # Errors
///
/// I/O failures, or a request that is not a version-13 WebSocket upgrade
/// (answered with `400` or `426` before the error).
pub fn server_handshake<S: Read + Write>(io: &mut S) -> io::Result<ServerUpgrade> {
    let (head, rest) = read_head(io)?;
    let head = String::from_utf8_lossy(&head);
    let request_line = head.lines().next().unwrap_or_default();
    let is_upgrade = request_line.starts_with("GET ")
        && header(&head, "Upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && header(&head, "Connection").is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        });
    let key = header(&head, "Sec-WebSocket-Key");
    let (Some(key), true) = (key, is_upgrade) else {
        refuse(io, "400 Bad Request", "")?;
        return Err(io::Error::other(format!(
            "not a WebSocket upgrade: {request_line}"
        )));
    };
    if header(&head, "Sec-WebSocket-Version").is_none_or(|v| v.trim() != "13") {
        refuse(io, "426 Upgrade Required", "Sec-WebSocket-Version: 13\r\n")?;
        return Err(io::Error::other("WebSocket version other than 13"));
    }
    let offers_sip = header(&head, "Sec-WebSocket-Protocol")
        .is_some_and(|v| v.split(',').any(|p| p.trim().eq_ignore_ascii_case("sip")));
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         {}\r\n",
        accept_key(&key),
        if offers_sip {
            "Sec-WebSocket-Protocol: sip\r\n"
        } else {
            ""
        }
    );
    io.write_all(response.as_bytes())?;
    io.flush()?;
    Ok(ServerUpgrade {
        path: request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_owned(),
        origin: header(&head, "Origin"),
        rest,
    })
}

/// Answer a bad upgrade request and let the caller drop the peer.
fn refuse<S: Write>(io: &mut S, status: &str, extra: &str) -> io::Result<()> {
    io.write_all(format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\n\r\n").as_bytes())?;
    io.flush()
}

/// Read up to and including the first `\r\n\r\n`; the rest of what was read
/// comes back separately.
fn read_head<R: Read>(io: &mut R) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = find(&head, b"\r\n\r\n") {
            let rest = head.split_off(end + 4);
            return Ok((head, rest));
        }
        if head.len() > MAX_HEAD {
            return Err(io::Error::other("WebSocket handshake head too long"));
        }
        match io.read(&mut chunk)? {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed during the WebSocket handshake",
                ));
            }
            n => head.extend_from_slice(&chunk[..n]),
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The value of header `name` in an HTTP head, case-insensitively; several
/// occurrences join with commas (as `Sec-WebSocket-Protocol` may repeat).
fn header(head: &str, name: &str) -> Option<String> {
    let values: Vec<&str> = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .collect();
    (!values.is_empty()).then(|| values.join(","))
}

// ---------------------------------------------------------------------------
// Frames (RFC 6455 §5)
// ---------------------------------------------------------------------------

/// A frame's opcode (RFC 6455 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// A later fragment of a message.
    Continuation = 0x0,
    /// A text message (what RFC 7118 §5 has the client send).
    Text = 0x1,
    /// A binary message.
    Binary = 0x2,
    /// Close, with an optional status code and reason.
    Close = 0x8,
    /// Ping: the peer expects a pong with the same payload.
    Ping = 0x9,
    /// Pong.
    Pong = 0xA,
}

impl Opcode {
    fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            _ => return None,
        })
    }
}

/// Encode one unfragmented frame (FIN set). `mask` is the client's key:
/// a client masks every frame it sends, a server none (RFC 6455 §5.3).
#[must_use]
#[allow(clippy::cast_possible_truncation)] // each cast follows a range check
pub fn frame(opcode: Opcode, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode as u8);
    let mask_bit = if mask.is_some() { 0x80 } else { 0x00 };
    let len = payload.len();
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= usize::from(u16::MAX) {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// A fresh masking key for a client frame.
#[must_use]
pub fn mask_key(rng: &mut Rng) -> [u8; 4] {
    let mut key = [0u8; 4];
    rng.fill(&mut key);
    key
}

/// What the peer sent, once whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsEvent {
    /// A data message (text or binary), fragments reassembled.
    Message(Vec<u8>),
    /// A ping to answer with a pong carrying the same payload.
    Ping(Vec<u8>),
    /// A close frame; its payload goes back in the answering close.
    Close(Vec<u8>),
}

/// A protocol violation by the peer; the connection is unusable after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// An opcode RFC 6455 does not define.
    Opcode(u8),
    /// A continuation frame with no message open, or a new data frame
    /// while one is.
    Fragmentation,
    /// A message beyond [`MAX_MESSAGE`].
    TooLarge,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opcode(op) => write!(f, "WebSocket frame with reserved opcode {op:#x}"),
            Self::Fragmentation => f.write_str("WebSocket fragment out of sequence"),
            Self::TooLarge => write!(f, "WebSocket message over {MAX_MESSAGE} bytes"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Accumulates stream bytes and yields whole WebSocket messages and the
/// control frames the reader must answer.
#[derive(Debug, Default)]
pub struct WsFramer {
    buf: Vec<u8>,
    /// The fragments of the message being reassembled.
    message: Vec<u8>,
    /// A fragmented message is open (its first frame had FIN clear).
    open: bool,
}

/// A parsed frame header.
struct Header {
    len: usize,
    fin: bool,
    opcode: Opcode,
    mask: Option<[u8; 4]>,
    payload_len: usize,
}

impl WsFramer {
    /// A framer with an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append freshly read bytes.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next whole event, `Ok(None)` when more bytes are needed. Pongs
    /// are consumed silently.
    ///
    /// # Errors
    ///
    /// A protocol violation ([`FrameError`]); drop the connection.
    pub fn next_event(&mut self) -> Result<Option<WsEvent>, FrameError> {
        loop {
            let Some(header) = self.header()? else {
                return Ok(None);
            };
            let total = header.len + header.payload_len;
            if self.buf.len() < total {
                return Ok(None);
            }
            let mut payload = self.buf[header.len..total].to_vec();
            if let Some(key) = header.mask {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= key[i % 4];
                }
            }
            self.buf.drain(..total);
            match header.opcode {
                Opcode::Continuation => {
                    if !self.open {
                        return Err(FrameError::Fragmentation);
                    }
                    if self.message.len() + payload.len() > MAX_MESSAGE {
                        return Err(FrameError::TooLarge);
                    }
                    self.message.extend_from_slice(&payload);
                    if header.fin {
                        self.open = false;
                        return Ok(Some(WsEvent::Message(std::mem::take(&mut self.message))));
                    }
                }
                Opcode::Text | Opcode::Binary => {
                    if self.open {
                        return Err(FrameError::Fragmentation);
                    }
                    if header.fin {
                        return Ok(Some(WsEvent::Message(payload)));
                    }
                    self.open = true;
                    self.message = payload;
                }
                Opcode::Close => return Ok(Some(WsEvent::Close(payload))),
                Opcode::Ping => return Ok(Some(WsEvent::Ping(payload))),
                Opcode::Pong => {}
            }
        }
    }

    /// Parse the header at the front of the buffer, `None` when incomplete.
    fn header(&self) -> Result<Option<Header>, FrameError> {
        let buf = &self.buf;
        let (Some(&b0), Some(&b1)) = (buf.first(), buf.get(1)) else {
            return Ok(None);
        };
        let opcode = Opcode::from_bits(b0 & 0x0F).ok_or(FrameError::Opcode(b0 & 0x0F))?;
        let masked = b1 & 0x80 != 0;
        let (payload_len, mut len) = match b1 & 0x7F {
            126 => {
                let Some(bytes) = buf.get(2..4) else {
                    return Ok(None);
                };
                (usize::from(u16::from_be_bytes([bytes[0], bytes[1]])), 4)
            }
            127 => {
                let Some(bytes) = buf.get(2..10) else {
                    return Ok(None);
                };
                let mut raw = [0u8; 8];
                raw.copy_from_slice(bytes);
                let n = u64::from_be_bytes(raw);
                (usize::try_from(n).map_err(|_| FrameError::TooLarge)?, 10)
            }
            n => (usize::from(n), 2),
        };
        if payload_len > MAX_MESSAGE {
            return Err(FrameError::TooLarge);
        }
        let mask = if masked {
            let Some(bytes) = buf.get(len..len + 4) else {
                return Ok(None);
            };
            len += 4;
            Some([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            None
        };
        Ok(Some(Header {
            len,
            fin: b0 & 0x80 != 0,
            opcode,
            mask,
            payload_len,
        }))
    }
}

// ---------------------------------------------------------------------------
// One wire for the two write paths
// ---------------------------------------------------------------------------

/// What a connection carries: raw SIP, or WebSocket frames, masked when
/// sipr dialed the connection (RFC 6455 §5.3: only the client masks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wire {
    /// SIP straight on the stream.
    Sip,
    /// WebSocket frames.
    Ws {
        /// Mask every frame (sipr is the WebSocket client here).
        mask: bool,
    },
}

impl Wire {
    /// The wire of a connection sipr dialed.
    pub(crate) fn dialed(framing: Framing) -> Self {
        match framing {
            Framing::Sip => Self::Sip,
            Framing::WebSocket => Self::Ws { mask: true },
        }
    }

    /// The wire of a connection sipr accepted.
    pub(crate) fn accepted(framing: Framing) -> Self {
        match framing {
            Framing::Sip => Self::Sip,
            Framing::WebSocket => Self::Ws { mask: false },
        }
    }

    pub(crate) fn framing(self) -> Framing {
        match self {
            Self::Sip => Framing::Sip,
            Self::Ws { .. } => Framing::WebSocket,
        }
    }

    /// Write `payload` as one message and flush: `opcode` is `Text` for a
    /// SIP message (RFC 7118 §5) and `Pong`/`Close` for a control answer;
    /// a SIP stream writes the bytes as they are. Callers hold the
    /// connection's lock, so frames never interleave.
    pub(crate) fn write(
        self,
        out: &mut impl Write,
        opcode: Opcode,
        payload: &[u8],
        rng: &Mutex<Rng>,
    ) -> io::Result<()> {
        match self {
            Self::Sip => out.write_all(payload)?,
            Self::Ws { mask } => {
                let key = mask.then(|| mask_key(&mut lock(rng)));
                out.write_all(&frame(opcode, payload, key))?;
            }
        }
        out.flush()
    }
}

/// Lock a mutex, poisoned or not: the guarded state is a socket table or
/// an RNG, usable after a panic elsewhere.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

// ---------------------------------------------------------------------------
// One framer for the two read loops
// ---------------------------------------------------------------------------

/// What a read loop gets from [`StreamFramer::next_message`].
#[derive(Debug)]
pub enum Next {
    /// A whole SIP message.
    Message(Vec<u8>),
    /// More bytes are needed.
    NeedMore,
    /// The connection is over: a close frame answered (`clean`), or a
    /// protocol violation.
    Closed {
        /// An orderly close, as opposed to an error.
        clean: bool,
    },
}

/// The SIP framer or the WebSocket framer behind one interface, so the TCP
/// and TLS read loops do not care which framing a connection carries.
#[derive(Debug)]
pub enum StreamFramer {
    /// `Content-Length` framing.
    Sip(TcpFramer),
    /// WebSocket framing.
    Ws(WsFramer),
}

impl StreamFramer {
    /// A framer for `framing`, seeded with the bytes that arrived with the
    /// handshake (empty for SIP framing).
    #[must_use]
    pub fn new(framing: Framing, initial: &[u8]) -> Self {
        let mut framer = match framing {
            Framing::Sip => Self::Sip(TcpFramer::new()),
            Framing::WebSocket => Self::Ws(WsFramer::new()),
        };
        framer.push(initial);
        framer
    }

    /// Append freshly read bytes.
    pub fn push(&mut self, data: &[u8]) {
        match self {
            Self::Sip(f) => f.push(data),
            Self::Ws(f) => f.push(data),
        }
    }

    /// The next SIP message. Under WebSocket framing a ping is answered
    /// with a pong and a close with a close through `reply`, which frames
    /// and writes under the connection's lock; SIP framing never calls it.
    pub fn next_message(&mut self, reply: &mut dyn FnMut(Opcode, &[u8]) -> io::Result<()>) -> Next {
        match self {
            Self::Sip(f) => f.next_message().map_or(Next::NeedMore, Next::Message),
            Self::Ws(f) => loop {
                match f.next_event() {
                    Ok(Some(WsEvent::Message(raw))) => return Next::Message(raw),
                    Ok(Some(WsEvent::Ping(payload))) => {
                        if reply(Opcode::Pong, &payload).is_err() {
                            return Next::Closed { clean: false };
                        }
                    }
                    Ok(Some(WsEvent::Close(payload))) => {
                        let _ = reply(Opcode::Close, &payload);
                        return Next::Closed { clean: true };
                    }
                    Ok(None) => return Next::NeedMore,
                    Err(_) => return Next::Closed { clean: false },
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// RFC 6455 §4.2.2's worked example.
    #[test]
    fn accept_key_matches_the_rfc_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// RFC 6455 §5.7's example frames, encoded and decoded.
    #[test]
    fn rfc_example_frames_round_trip() {
        assert_eq!(frame(Opcode::Text, b"Hello", None), b"\x81\x05Hello");
        assert_eq!(
            frame(Opcode::Text, b"Hello", Some([0x37, 0xfa, 0x21, 0x3d])),
            b"\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58"
        );
        assert_eq!(frame(Opcode::Ping, b"Hello", None), b"\x89\x05Hello");
        let long = frame(Opcode::Binary, &[7u8; 256], None);
        assert_eq!(&long[..4], b"\x82\x7e\x01\x00");
        assert_eq!(long.len(), 4 + 256);
        let huge = frame(Opcode::Binary, &[7u8; 65_536], None);
        assert_eq!(&huge[..10], b"\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x00");
        assert_eq!(huge.len(), 10 + 65_536);

        let mut framer = WsFramer::new();
        framer.push(b"\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58");
        framer.push(&long);
        framer.push(&huge);
        assert_eq!(
            framer.next_event(),
            Ok(Some(WsEvent::Message(b"Hello".to_vec())))
        );
        assert_eq!(
            framer.next_event(),
            Ok(Some(WsEvent::Message(vec![7u8; 256])))
        );
        assert_eq!(
            framer.next_event(),
            Ok(Some(WsEvent::Message(vec![7u8; 65_536])))
        );
        assert_eq!(framer.next_event(), Ok(None));
    }

    /// RFC 6455 §5.7: a fragmented text message, with a ping between the
    /// fragments (control frames may interleave, §5.4), delivered whole.
    #[test]
    fn fragments_reassemble_and_control_frames_interleave() {
        let mut framer = WsFramer::new();
        framer.push(b"\x01\x03Hel");
        framer.push(b"\x89\x02hi");
        framer.push(b"\x80\x02lo");
        framer.push(b"\x8a\x00");
        framer.push(b"\x88\x02\x03\xe8");
        assert_eq!(framer.next_event(), Ok(Some(WsEvent::Ping(b"hi".to_vec()))));
        assert_eq!(
            framer.next_event(),
            Ok(Some(WsEvent::Message(b"Hello".to_vec())))
        );
        // The pong is consumed silently; the close comes through.
        assert_eq!(
            framer.next_event(),
            Ok(Some(WsEvent::Close(vec![0x03, 0xe8])))
        );
    }

    #[test]
    fn frames_arrive_byte_by_byte() {
        let encoded = frame(Opcode::Text, b"INVITE", Some([1, 2, 3, 4]));
        let mut framer = WsFramer::new();
        for b in &encoded[..encoded.len() - 1] {
            framer.push(&[*b]);
            assert_eq!(framer.next_event(), Ok(None));
        }
        framer.push(&encoded[encoded.len() - 1..]);
        assert_eq!(
            framer.next_event(),
            Ok(Some(WsEvent::Message(b"INVITE".to_vec())))
        );
    }

    #[test]
    fn protocol_violations_are_errors_not_panics() {
        let mut framer = WsFramer::new();
        framer.push(b"\x80\x02lo"); // continuation with nothing open
        assert_eq!(framer.next_event(), Err(FrameError::Fragmentation));

        let mut framer = WsFramer::new();
        framer.push(b"\x01\x03Hel\x81\x02lo"); // a new text frame inside a message
        assert_eq!(framer.next_event(), Err(FrameError::Fragmentation));

        let mut framer = WsFramer::new();
        framer.push(b"\x83\x00"); // reserved opcode 3
        assert_eq!(framer.next_event(), Err(FrameError::Opcode(3)));

        let mut framer = WsFramer::new();
        framer.push(b"\x82\x7f\xff\xff\xff\xff\xff\xff\xff\xff"); // 2^64-1 bytes
        assert_eq!(framer.next_event(), Err(FrameError::TooLarge));
    }

    #[test]
    fn handshake_completes_over_a_loopback_pair() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let rest = server_handshake(&mut sock).expect("server handshake").rest;
            // The client's first frame may ride in with the request.
            let mut framer = WsFramer::new();
            framer.push(&rest);
            let mut buf = [0u8; 64];
            loop {
                match framer.next_event() {
                    Ok(None) => {
                        let n = sock.read(&mut buf).expect("read");
                        framer.push(&buf[..n]);
                    }
                    other => return other,
                }
            }
        });
        let mut sock = TcpStream::connect(addr).expect("connect");
        let mut rng = Rng::new(7);
        let rest = client_handshake(
            &mut sock,
            &addr.to_string(),
            &WsRequest::default(),
            &mut rng,
        )
        .expect("client");
        assert!(rest.is_empty());
        let key = mask_key(&mut rng);
        sock.write_all(&frame(Opcode::Text, b"OPTIONS", Some(key)))
            .expect("send");
        assert_eq!(
            server.join().expect("server"),
            Ok(Some(WsEvent::Message(b"OPTIONS".to_vec())))
        );
    }

    /// `--sipr-ws-path` / `--sipr-ws-origin`: the request line carries the
    /// path and the head an `Origin`, and the server side reports both.
    #[test]
    fn client_request_carries_path_and_origin_and_the_server_reports_them() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            server_handshake(&mut sock).expect("server handshake")
        });
        let mut sock = TcpStream::connect(addr).expect("connect");
        let request = WsRequest::new("/sip/ws", Some("https://example.org")).expect("request");
        client_handshake(&mut sock, &addr.to_string(), &request, &mut Rng::new(5)).expect("client");
        let seen = server.join().expect("server");
        assert_eq!(seen.path, "/sip/ws");
        assert_eq!(seen.origin.as_deref(), Some("https://example.org"));
        assert!(seen.rest.is_empty());
    }

    #[test]
    fn a_ws_request_is_validated() {
        assert!(WsRequest::default().is_default());
        assert_eq!(WsRequest::default().path(), "/");
        assert_eq!(WsRequest::default().origin(), None);
        let ok = WsRequest::new("/", Some("http://h:80")).expect("ok");
        assert!(!ok.is_default());
        assert_eq!(ok.origin(), Some("http://h:80"));
        for (path, origin) in [
            ("sip", None),
            ("", None),
            ("/a b", None),
            ("/x\r\nEvil: 1", None),
            ("/", Some("")),
            ("/", Some("https://h\r\nEvil: 1")),
            ("/", Some("a b")),
        ] {
            assert!(WsRequest::new(path, origin).is_err(), "{path:?} {origin:?}");
        }
    }

    #[test]
    fn server_refuses_a_plain_http_request_and_an_old_version() {
        for (request, status) in [
            ("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "400"),
            (
                "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
                "426",
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr");
            let server = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().expect("accept");
                server_handshake(&mut sock).is_err()
            });
            let mut sock = TcpStream::connect(addr).expect("connect");
            sock.write_all(request.as_bytes()).expect("write");
            let mut reply = String::new();
            sock.read_to_string(&mut reply).expect("read");
            assert!(reply.starts_with(&format!("HTTP/1.1 {status}")), "{reply}");
            assert!(server.join().expect("server"));
        }
    }

    #[test]
    fn client_rejects_a_wrong_accept_key() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let _ = read_head(&mut sock);
            let _ = sock.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Accept: bogus\r\n\r\n",
            );
        });
        let mut sock = TcpStream::connect(addr).expect("connect");
        let err = client_handshake(&mut sock, "x", &WsRequest::default(), &mut Rng::new(1))
            .expect_err("refused");
        assert!(err.to_string().contains("Sec-WebSocket-Accept"), "{err}");
    }

    #[test]
    fn stream_framer_answers_pings_and_closes() {
        let mut replies: Vec<(Opcode, Vec<u8>)> = Vec::new();
        let mut reply = |op: Opcode, payload: &[u8]| {
            replies.push((op, payload.to_vec()));
            Ok(())
        };
        let mut framer = StreamFramer::new(Framing::WebSocket, b"\x89\x02hi");
        assert!(matches!(framer.next_message(&mut reply), Next::NeedMore));
        framer.push(&frame(Opcode::Text, b"BYE", Some([9, 9, 9, 9])));
        assert!(matches!(framer.next_message(&mut reply), Next::Message(m) if m == b"BYE"));
        framer.push(b"\x88\x00");
        assert!(matches!(
            framer.next_message(&mut reply),
            Next::Closed { clean: true }
        ));

        let mut framer = StreamFramer::new(Framing::Sip, b"");
        framer.push(b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n");
        assert!(matches!(framer.next_message(&mut reply), Next::Message(_)));
        assert!(matches!(framer.next_message(&mut reply), Next::NeedMore));
        assert_eq!(
            replies,
            vec![(Opcode::Pong, b"hi".to_vec()), (Opcode::Close, Vec::new())]
        );
    }
}
