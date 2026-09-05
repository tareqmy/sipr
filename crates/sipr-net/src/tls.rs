//! TLS transport (`l1`): the TCP connection-per-peer model with a rustls
//! layer in between. Same framing ([`TcpFramer`]), same routing (writes go
//! back by peer address), same reliability rule (no SIP retransmissions).
//!
//! Verification semantics follow SIPp (`sslsocket.cpp`), not TLS best
//! practice — this is a test tool talking to lab equipment:
//! - No `-tls_ca`/`-tls_crl`: **no peer verification at all**. The client
//!   accepts any server certificate; the server requests none.
//! - With `-tls_ca` (or `-tls_crl`): the client verifies the chain but NOT
//!   the hostname (SIPp never calls `X509_check_host`), and the server
//!   demands and verifies a client certificate (mutual TLS).
//! - The client always presents its certificate when asked (SIPp loads the
//!   cert/key pair into both contexts).
//!
//! Deliberate divergences from SIPp, recorded in docs/SIPP_COMPAT.md §6:
//! - A failed *inbound* handshake drops that connection with a stderr
//!   warning; SIPp kills the whole process on `SSL_accept` failure.
//! - TLS 1.0/1.1 are rejected (`rustls` has no pre-1.2 support; SIPp's
//!   floor is 1.0).
//! - Encrypted private keys are rejected (SIPp decrypts with a hardcoded
//!   passphrase).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig};

use crate::message::Inbound;
use crate::rng::Rng;
use crate::tcp::TcpFramer;
use crate::transport::{InboundPacket, NetEvent, TransportConfig};

/// One read from the socket (ciphertext); the framer copes with any split.
const READ_CHUNK: usize = 64 * 1024;

/// TLS-specific configuration (`-tls_*` flags), alongside [`TransportConfig`].
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Certificate chain file, PEM (`-tls_cert`; SIPp default `cacert.pem`).
    pub cert: PathBuf,
    /// Private key file, PEM (`-tls_key`; SIPp default `cakey.pem`).
    pub key: PathBuf,
    /// CA file (`-tls_ca`); presence switches peer verification ON.
    pub ca: Option<PathBuf>,
    /// CRL file (`-tls_crl`); presence also switches verification ON.
    pub crl: Option<PathBuf>,
    /// Version pin (`-tls_version`); `Auto` negotiates 1.2/1.3.
    pub version: TlsVersion,
}

/// `-tls_version` argument. SIPp autonegotiates from 1.0 up by default and
/// can pin any of 1.0–1.3; rustls starts at 1.2, so 1.0/1.1 are rejected at
/// CLI parse time and never reach this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsVersion {
    /// Negotiate TLS 1.2 or 1.3.
    #[default]
    Auto,
    /// Pin TLS 1.2.
    V1_2,
    /// Pin TLS 1.3.
    V1_3,
}

impl TlsVersion {
    fn protocol_versions(self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        static V1_2_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
        static V1_3_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        match self {
            Self::Auto => rustls::DEFAULT_VERSIONS,
            Self::V1_2 => V1_2_ONLY,
            Self::V1_3 => V1_3_ONLY,
        }
    }
}

/// A live TLS connection: the rustls state machine plus a raw write handle.
///
/// Every `write_tls` (encrypt → socket) MUST happen while holding the `tls`
/// mutex — two threads interleaving TLS records on one stream corrupts it.
/// Blocking reads of ciphertext happen on the reader thread's own clone,
/// outside the lock.
struct TlsConn {
    tls: Arc<Mutex<Connection>>,
    sock: TcpStream,
}

/// Live connections keyed by peer address.
type Conns = Arc<Mutex<HashMap<SocketAddr, TlsConn>>>;

/// The `l1` TLS transport: one TLS-over-TCP connection per peer, framed
/// reader threads, writes routed back by peer address.
pub struct TlsTransport {
    local_addr: SocketAddr,
    conns: Conns,
    send_rng: Mutex<Rng>,
    send_loss_pct: f64,
    sink: Sender<NetEvent>,
    /// Client configuration, kept for per-call connections (`ln`).
    client: Option<Arc<ClientConfig>>,
    /// Kept so the accept loop lives as long as the transport (server only).
    _accept: Option<std::thread::JoinHandle<()>>,
}

/// A per-call TLS connection (`-t ln`): dialed and handshaken for one call,
/// read by its own thread into the transport's sink; dropping it closes it.
pub struct TlsCallConn {
    tls: Arc<Mutex<Connection>>,
    sock: TcpStream,
    local_addr: SocketAddr,
}

impl TlsCallConn {
    /// The connection's local address (`[local_port]` for this call).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for TlsCallConn {
    fn drop(&mut self) {
        if let Ok(mut tls) = self.tls.lock() {
            tls.send_close_notify();
            let mut out = &self.sock;
            while tls.wants_write() {
                if tls.write_tls(&mut out).is_err() {
                    break;
                }
            }
        }
        let _ = self.sock.shutdown(std::net::Shutdown::Both);
    }
}

impl TlsTransport {
    /// Client (`UAC`): dial `remote`, complete the TLS handshake, and start
    /// framing responses.
    ///
    /// # Errors
    ///
    /// Certificate/key loading, connection, or handshake failures.
    pub fn connect(
        config: &TransportConfig,
        tls_config: &TlsConfig,
        sink: Sender<NetEvent>,
        remote: SocketAddr,
    ) -> std::io::Result<Self> {
        let client_config = client_config(tls_config)?;
        let mut sock = TcpStream::connect(remote)?;
        let local_addr = sock.local_addr()?;
        let peer = sock.peer_addr()?;
        // SIPp only sends SNI for named targets; ours is already a resolved
        // address, and rustls sends no SNI for IP names — behavior matches.
        let name = ServerName::from(peer.ip());
        let mut tls = Connection::from(
            ClientConnection::new(Arc::clone(&client_config), name)
                .map_err(std::io::Error::other)?,
        );
        complete_handshake(&mut tls, &mut sock)
            .map_err(|e| std::io::Error::other(format!("TLS handshake with {remote}: {e}")))?;
        let conns: Conns = Arc::new(Mutex::new(HashMap::new()));
        register(&conns, peer, sock, tls, &sink)?;
        Ok(Self {
            local_addr,
            conns,
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0021)),
            send_loss_pct: config.send_loss_pct,
            sink,
            client: Some(client_config),
            _accept: None,
        })
    }

    /// Client in `ln` mode: no connection yet — each call dials its own with
    /// [`Self::connect_call`].
    ///
    /// # Errors
    ///
    /// Certificate/key loading failures.
    pub fn client_pool(
        config: &TransportConfig,
        tls_config: &TlsConfig,
        sink: Sender<NetEvent>,
    ) -> std::io::Result<Self> {
        let ip = config.local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        Ok(Self {
            local_addr: SocketAddr::new(ip, 0),
            conns: Arc::new(Mutex::new(HashMap::new())),
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0023)),
            send_loss_pct: config.send_loss_pct,
            sink,
            client: Some(client_config(tls_config)?),
            _accept: None,
        })
    }

    /// Dial and handshake a per-call connection to `remote` (`-t ln`).
    ///
    /// # Errors
    ///
    /// Connection or handshake failures (the call fails, not the run); a
    /// server-side transport has no client configuration.
    pub fn connect_call(&self, remote: SocketAddr) -> std::io::Result<TlsCallConn> {
        let client_config = self.client.clone().ok_or_else(|| {
            std::io::Error::other("per-call TLS connections need a client configuration")
        })?;
        let mut sock = TcpStream::connect(remote)?;
        let local_addr = sock.local_addr()?;
        let peer = sock.peer_addr()?;
        let name = ServerName::from(peer.ip());
        let mut tls = Connection::from(
            ClientConnection::new(client_config, name).map_err(std::io::Error::other)?,
        );
        complete_handshake(&mut tls, &mut sock)
            .map_err(|e| std::io::Error::other(format!("TLS handshake with {remote}: {e}")))?;
        let read_sock = sock.try_clone()?;
        let tls = Arc::new(Mutex::new(tls));
        let reader_tls = Arc::clone(&tls);
        let sink = self.sink.clone();
        std::thread::Builder::new()
            .name("sipr-tls-call".into())
            .spawn(move || read_loop(read_sock, &reader_tls, peer, &sink))?;
        Ok(TlsCallConn {
            tls,
            sock,
            local_addr,
        })
    }

    /// Send `data` on a per-call connection, honoring simulated loss.
    ///
    /// # Errors
    ///
    /// Encryption or write failures.
    pub fn send_via(
        &self,
        conn: &TlsCallConn,
        data: &[u8],
        lost_pct: Option<f64>,
    ) -> std::io::Result<bool> {
        if self.simulate_loss(lost_pct) {
            return Ok(false);
        }
        write_tls(&conn.tls, &conn.sock, data)?;
        Ok(true)
    }

    fn simulate_loss(&self, lost_pct: Option<f64>) -> bool {
        let pct = lost_pct.unwrap_or(self.send_loss_pct);
        if pct <= 0.0 {
            return false;
        }
        let mut rng = match self.send_rng.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        rng.chance_pct(pct)
    }

    /// Server (`UAS`): bind a listener and accept connections. Each accepted
    /// connection handshakes on its own thread, so a slow or failing client
    /// never stalls the listener or the process (unlike SIPp, which treats an
    /// `SSL_accept` failure as fatal).
    ///
    /// # Errors
    ///
    /// Certificate/key loading or bind failures.
    pub fn listen(
        config: &TransportConfig,
        tls_config: &TlsConfig,
        sink: Sender<NetEvent>,
    ) -> std::io::Result<Self> {
        let server_config = server_config(tls_config)?;
        let ip = config.local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let listener = TcpListener::bind(SocketAddr::new(ip, config.port.unwrap_or(0)))?;
        let local_addr = listener.local_addr()?;
        let conns: Conns = Arc::new(Mutex::new(HashMap::new()));
        let accept_conns = conns.clone();
        let accept_sink = sink.clone();
        let accept = std::thread::Builder::new()
            .name("sipr-tls-accept".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut sock) = stream else { continue };
                    let Ok(peer) = sock.peer_addr() else {
                        continue;
                    };
                    let Ok(server_conn) = rustls::ServerConnection::new(server_config.clone())
                    else {
                        continue;
                    };
                    let conns = accept_conns.clone();
                    let sink = accept_sink.clone();
                    // Handshake per connection, off the accept loop.
                    let _ = std::thread::Builder::new()
                        .name("sipr-tls-handshake".into())
                        .spawn(move || {
                            let mut tls = Connection::from(server_conn);
                            match complete_handshake(&mut tls, &mut sock) {
                                Ok(()) => {
                                    let _ = register(&conns, peer, sock, tls, &sink);
                                }
                                Err(e) => {
                                    // Loud but per-peer: one bad client must
                                    // not stop a server.
                                    eprintln!(
                                        "sipr: warning: TLS handshake with {peer} failed: {e}"
                                    );
                                }
                            }
                        });
                }
            })
            .ok();
        Ok(Self {
            local_addr,
            conns,
            send_rng: Mutex::new(Rng::new(config.loss_seed ^ 0x5EED_0022)),
            send_loss_pct: config.send_loss_pct,
            sink,
            // A server still dials out under `-rsa`; the same identity serves.
            client: client_config(tls_config).ok(),
            _accept: accept,
        })
    }

    /// The bound local address (a real ephemeral port when `-p` was omitted).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send `data` to the connection for `to`, honoring simulated loss.
    ///
    /// Returns `true` when the bytes were written (`false` = simulated drop).
    ///
    /// # Errors
    ///
    /// No connection exists for `to`, or encryption/write failed.
    pub fn send_to(
        &self,
        data: &[u8],
        to: SocketAddr,
        lost_pct: Option<f64>,
    ) -> std::io::Result<bool> {
        if self.simulate_loss(lost_pct) {
            return Ok(false); // simulated app-layer loss
        }
        let map = match self.conns.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(conn) = map.get(&to) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("no TLS connection to {to}"),
            ));
        };
        write_tls(&conn.tls, &conn.sock, data)?;
        Ok(true)
    }
}

/// Encrypt `data` under the connection lock and push the records out.
fn write_tls(tls: &Mutex<Connection>, sock: &TcpStream, data: &[u8]) -> std::io::Result<()> {
    let mut tls = match tls.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    tls.writer().write_all(data)?;
    let mut out = sock;
    while tls.wants_write() {
        tls.write_tls(&mut out)?;
    }
    out.flush()
}

/// Drive the handshake to completion on a blocking socket.
fn complete_handshake(tls: &mut Connection, sock: &mut TcpStream) -> std::io::Result<()> {
    while tls.is_handshaking() {
        tls.complete_io(sock)?;
    }
    Ok(())
}

/// Register an established connection under `peer`: store the write handle
/// and spawn a framed reader (on a socket clone) that delivers into `sink`
/// and deregisters on close.
fn register(
    conns: &Conns,
    peer: SocketAddr,
    sock: TcpStream,
    tls: Connection,
    sink: &Sender<NetEvent>,
) -> std::io::Result<()> {
    let read_sock = sock.try_clone()?;
    let tls = Arc::new(Mutex::new(tls));
    let reader_tls = tls.clone();
    if let Ok(mut map) = conns.lock() {
        map.insert(peer, TlsConn { tls, sock });
    }
    let sink = sink.clone();
    let conns = conns.clone();
    std::thread::Builder::new()
        .name("sipr-tls-recv".into())
        .spawn(move || {
            read_loop(read_sock, &reader_tls, peer, &sink);
            if let Ok(mut map) = conns.lock() {
                map.remove(&peer);
            }
        })
        .ok();
    Ok(())
}

/// Frame everything arriving on one connection until it closes or errors.
/// Ciphertext is read blocking (no lock held), then decrypted under the
/// connection lock. A per-connection failure deregisters that peer but never
/// signals the engine — one client hanging up must not stop a server.
fn read_loop(
    mut sock: TcpStream,
    tls: &Arc<Mutex<Connection>>,
    peer: SocketAddr,
    sink: &Sender<NetEvent>,
) {
    let mut framer = TcpFramer::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut plain = vec![0u8; READ_CHUNK];
    // First pass runs with an empty cipher slice: handshake reads can
    // coalesce the peer's first data records (TLS 1.3 sends Finished and
    // early traffic back to back), so drain buffered plaintext before ever
    // blocking on the socket.
    let mut n = 0;
    'outer: loop {
        let mut cipher = &buf[..n];
        loop {
            // Decrypt under the lock; deliver after releasing it.
            let closed = {
                let mut tls = match tls.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                if !cipher.is_empty() && tls.read_tls(&mut cipher).is_err() {
                    break 'outer;
                }
                let Ok(state) = tls.process_new_packets() else {
                    break 'outer; // TLS protocol violation
                };
                // The peer may have triggered a response (key update, ack).
                let mut out = &sock;
                while tls.wants_write() {
                    if tls.write_tls(&mut out).is_err() {
                        break 'outer;
                    }
                }
                loop {
                    match tls.reader().read(&mut plain) {
                        Ok(0) => break, // no plaintext without close_notify
                        Ok(n) => framer.push(&plain[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break 'outer,
                    }
                }
                state.peer_has_closed()
            };
            while let Some(raw) = framer.next_message() {
                let event = match Inbound::parse(&raw) {
                    Ok(message) => NetEvent::Packet(InboundPacket {
                        message,
                        raw,
                        from: peer,
                        received_at: Instant::now(),
                    }),
                    Err(reason) => NetEvent::Garbage { from: peer, reason },
                };
                if sink.send(event).is_err() {
                    return; // engine gone
                }
            }
            if closed {
                break 'outer; // clean close_notify
            }
            if cipher.is_empty() {
                break;
            }
        }
        n = match sock.read(&mut buf) {
            Ok(0) => break, // peer closed
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => 0,
            Err(_) => break,
        };
    }
}

// ---------------------------------------------------------------------------
// rustls config assembly
// ---------------------------------------------------------------------------

/// The crypto provider: `ring`, chosen over the default `aws-lc-rs` for its
/// dependency-light build (docs/CONVENTIONS.md §Dependencies).
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Read a PEM certificate chain.
fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("cannot read TLS certificate file {}: {e}", path.display()),
        )
    })?;
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(file)).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(std::io::Error::other(format!(
            "no certificates found in {}",
            path.display()
        )));
    }
    Ok(certs)
}

/// Read a PEM private key (PKCS#8, PKCS#1, or SEC1 — unencrypted only;
/// SIPp decrypts with a hardcoded passphrase, which we do not reproduce).
fn load_key(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("cannot read TLS key file {}: {e}", path.display()),
        )
    })?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(file))?.ok_or_else(|| {
        std::io::Error::other(format!(
            "no private key found in {} (encrypted keys are not supported)",
            path.display()
        ))
    })
}

/// CA roots from `-tls_ca` (empty store when only `-tls_crl` was given —
/// verification is then on but nothing can validate, matching SIPp).
fn root_store(tls: &TlsConfig) -> std::io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    if let Some(ca) = &tls.ca {
        for cert in load_certs(ca)? {
            roots.add(cert).map_err(std::io::Error::other)?;
        }
    }
    Ok(roots)
}

/// CRLs from `-tls_crl`.
fn load_crls(path: &Path) -> std::io::Result<Vec<CertificateRevocationListDer<'static>>> {
    let file = std::fs::File::open(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("cannot read TLS CRL file {}: {e}", path.display()),
        )
    })?;
    rustls_pemfile::crls(&mut std::io::BufReader::new(file)).collect::<Result<_, _>>()
}

/// Whether `-tls_ca`/`-tls_crl` switched peer verification on (SIPp's rule).
fn verification_enabled(tls: &TlsConfig) -> bool {
    tls.ca.is_some() || tls.crl.is_some()
}

/// Client config: SIPp semantics — anonymous-peer trust by default, chain
/// (but not hostname) verification when a CA is given, and our cert always
/// offered if the server asks.
fn client_config(tls: &TlsConfig) -> std::io::Result<Arc<ClientConfig>> {
    let certs = load_certs(&tls.cert)?;
    let key = load_key(&tls.key)?;
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(tls.version.protocol_versions())
        .map_err(std::io::Error::other)?;
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = if verification_enabled(tls)
    {
        let mut builder = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store(tls)?),
            provider(),
        );
        if let Some(crl) = &tls.crl {
            builder = builder.with_crls(load_crls(crl)?);
        }
        let webpki = builder.build().map_err(std::io::Error::other)?;
        Arc::new(ChainOnlyVerifier { inner: webpki })
    } else {
        Arc::new(AcceptAnyServerCert {
            provider: provider(),
        })
    };
    let config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .map_err(std::io::Error::other)?;
    Ok(Arc::new(config))
}

/// Server config: no client auth by default; with a CA, demand and verify a
/// client certificate (SIPp's `SSL_VERIFY_PEER | FAIL_IF_NO_PEER_CERT`).
fn server_config(tls: &TlsConfig) -> std::io::Result<Arc<ServerConfig>> {
    let certs = load_certs(&tls.cert)?;
    let key = load_key(&tls.key)?;
    let builder = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(tls.version.protocol_versions())
        .map_err(std::io::Error::other)?;
    let config = if verification_enabled(tls) {
        let mut verifier_builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(root_store(tls)?),
            provider(),
        );
        if let Some(crl) = &tls.crl {
            verifier_builder = verifier_builder.with_crls(load_crls(crl)?);
        }
        let verifier = verifier_builder.build().map_err(std::io::Error::other)?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
    } else {
        builder.with_no_client_auth().with_single_cert(certs, key)
    }
    .map_err(std::io::Error::other)?;
    Ok(Arc::new(config))
}

/// SIPp with no `-tls_ca`: no verification at all. Handshake signatures are
/// still checked against the presented (untrusted) certificate — that is
/// protocol soundness, not trust.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// SIPp with `-tls_ca`: chain verification WITHOUT hostname matching (SIPp
/// never checks the peer identity against the target).
#[derive(Debug)]
struct ChainOnlyVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl rustls::client::danger::ServerCertVerifier for ChainOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use rustls::CertificateError;
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName)) => {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
                ..
            })) => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    const MSG: &[u8] =
        b"OPTIONS sip:x SIP/2.0\r\nCall-ID: s-1\r\nCSeq: 7 OPTIONS\r\nContent-Length: 0\r\n\r\n";

    /// Self-signed cert + key PEM files in a temp dir; returns the dir (keep
    /// it alive) and the TlsConfig pointing into it.
    fn test_identity() -> (tempfile::TempDir, TlsConfig) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        let config = TlsConfig {
            cert: cert_path,
            key: key_path,
            ca: None,
            crl: None,
            version: TlsVersion::Auto,
        };
        (dir, config)
    }

    fn config() -> TransportConfig {
        TransportConfig {
            local_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ..Default::default()
        }
    }

    #[test]
    fn client_server_roundtrip_and_reply() {
        let (_dir, tls) = test_identity();
        let (srv_tx, srv_rx) = mpsc::channel();
        let server = TlsTransport::listen(&config(), &tls, srv_tx).expect("listen");
        let srv_addr = server.local_addr();

        let (cli_tx, cli_rx) = mpsc::channel();
        let client = TlsTransport::connect(&config(), &tls, cli_tx, srv_addr).expect("connect");

        assert!(client.send_to(MSG, srv_addr, None).expect("send"));
        let from = match srv_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server rx")
        {
            NetEvent::Packet(p) => {
                assert_eq!(p.message.call_id(), Some("s-1"));
                p.from
            }
            other => panic!("expected Packet, got {other:?}"),
        };
        let reply =
            b"SIP/2.0 200 OK\r\nCall-ID: s-1\r\nCSeq: 7 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        assert!(server.send_to(reply, from, None).expect("reply"));
        match cli_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("client rx")
        {
            NetEvent::Packet(p) => assert_eq!(p.message.status_code(), Some(200)),
            other => panic!("expected Packet, got {other:?}"),
        }
    }

    #[test]
    fn mutual_tls_with_ca_roundtrips() {
        // Self-signed cert doubles as its own CA: chain verification passes
        // on both sides (client checks server, server demands client cert).
        let (_dir, mut tls) = test_identity();
        tls.ca = Some(tls.cert.clone());
        let (srv_tx, srv_rx) = mpsc::channel();
        let server = TlsTransport::listen(&config(), &tls, srv_tx).expect("listen");
        let srv_addr = server.local_addr();
        let (cli_tx, _cli_rx) = mpsc::channel();
        let client = TlsTransport::connect(&config(), &tls, cli_tx, srv_addr).expect("connect");
        assert!(client.send_to(MSG, srv_addr, None).expect("send"));
        match srv_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server rx")
        {
            NetEvent::Packet(p) => assert_eq!(p.message.call_id(), Some("s-1")),
            other => panic!("expected Packet, got {other:?}"),
        }
    }

    #[test]
    fn handshake_against_plain_tcp_fails() {
        // A listener that never speaks TLS: the client handshake must error,
        // not hang or panic.
        let (_dir, tls) = test_identity();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let srv = std::thread::spawn(move || {
            // Accept and slam the door.
            if let Ok((sock, _)) = listener.accept() {
                drop(sock);
            }
        });
        let (tx, _rx) = mpsc::channel();
        let result = TlsTransport::connect(&config(), &tls, tx, addr);
        assert!(result.is_err(), "handshake with a mute peer must fail");
        let _ = srv.join();
    }

    #[test]
    fn missing_cert_file_is_a_clear_error() {
        let (_dir, mut tls) = test_identity();
        tls.cert = PathBuf::from("/nonexistent/nope.pem");
        let (tx, _rx) = mpsc::channel();
        let err = TlsTransport::listen(&config(), &tls, tx)
            .map(|_| ())
            .expect_err("must fail");
        assert!(
            err.to_string().contains("nope.pem"),
            "error names the file: {err}"
        );
    }

    #[test]
    fn send_without_connection_errors() {
        let (_dir, tls) = test_identity();
        let (tx, _rx) = mpsc::channel();
        let server = TlsTransport::listen(&config(), &tls, tx).expect("listen");
        let nowhere = "127.0.0.1:9".parse().expect("addr");
        assert!(server.send_to(MSG, nowhere, None).is_err());
    }

    #[test]
    fn version_pin_1_3_negotiates() {
        let (_dir, mut tls) = test_identity();
        tls.version = TlsVersion::V1_3;
        let (srv_tx, srv_rx) = mpsc::channel();
        let server = TlsTransport::listen(&config(), &tls, srv_tx).expect("listen");
        let (cli_tx, _cli_rx) = mpsc::channel();
        let client =
            TlsTransport::connect(&config(), &tls, cli_tx, server.local_addr()).expect("connect");
        assert!(
            client
                .send_to(MSG, server.local_addr(), None)
                .expect("send")
        );
        assert!(
            srv_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "1.3-pinned handshake carries traffic"
        );
    }
}
