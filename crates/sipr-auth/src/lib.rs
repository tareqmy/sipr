//! `sipr-auth`: digest authentication (RFC 2617 / RFC 7616) backing the
//! `[authentication]` keyword (milestone M6).
//!
//! Flow: a `<recv auth="true">` on a 401/407 stores the parsed
//! [`Challenge`]; the next send's `[authentication]` keyword calls
//! [`authorization_header`] to produce the full `Authorization:` /
//! `Proxy-Authorization:` line. MD5 and SHA-256 with `qop="auth"` are
//! supported; hash primitives are in-tree (see `hash.rs`).

mod hash;

pub use hash::{md5_hex, sha256_hex};

/// Which digest algorithm the challenge requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// `MD5` (RFC 2617 default).
    #[default]
    Md5,
    /// `SHA-256` (RFC 7616).
    Sha256,
}

impl Algorithm {
    fn hash(self, data: &str) -> String {
        match self {
            Self::Md5 => md5_hex(data.as_bytes()),
            Self::Sha256 => sha256_hex(data.as_bytes()),
        }
    }

    fn token(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha256 => "SHA-256",
        }
    }
}

/// A parsed `WWW-Authenticate` / `Proxy-Authenticate` digest challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Protection realm.
    pub realm: String,
    /// Server nonce.
    pub nonce: String,
    /// Opaque blob to echo back, when present.
    pub opaque: Option<String>,
    /// Requested algorithm.
    pub algorithm: Algorithm,
    /// True when the server offered `qop="auth"`.
    pub qop_auth: bool,
    /// True when the challenge carried `stale=true` (nonce expired; retry
    /// with fresh nonce, same credentials).
    pub stale: bool,
    /// True when this came from a 407 (Proxy-Authenticate).
    pub proxy: bool,
}

/// Parse a digest challenge header value (the part after the header name).
///
/// Returns `None` for non-Digest schemes or when realm/nonce are missing.
#[must_use]
pub fn parse_challenge(value: &str, proxy: bool) -> Option<Challenge> {
    let rest = value.trim().strip_prefix("Digest")?.trim_start();
    let mut realm = None;
    let mut nonce = None;
    let mut opaque = None;
    let mut algorithm = Algorithm::Md5;
    let mut qop_auth = false;
    let mut stale = false;
    for (key, val) in parse_params(rest) {
        match key.to_ascii_lowercase().as_str() {
            "realm" => realm = Some(val),
            "nonce" => nonce = Some(val),
            "opaque" => opaque = Some(val),
            "algorithm" => {
                algorithm = match val.to_ascii_uppercase().as_str() {
                    "SHA-256" => Algorithm::Sha256,
                    _ => Algorithm::Md5, // MD5, MD5-sess (treated as MD5)
                };
            }
            "qop" => {
                qop_auth = val
                    .split(',')
                    .any(|q| q.trim().eq_ignore_ascii_case("auth"));
            }
            "stale" => stale = val.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    Some(Challenge {
        realm: realm?,
        nonce: nonce?,
        opaque,
        algorithm,
        qop_auth,
        stale,
        proxy,
    })
}

/// Split `k1="v1", k2=v2, ...` into pairs, handling quoted values.
fn parse_params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = s;
    loop {
        rest = rest.trim_start_matches([',', ' ', '\t']);
        let Some(eq) = rest.find('=') else { break };
        let key = rest[..eq].trim().to_owned();
        rest = &rest[eq + 1..];
        let value = if let Some(stripped) = rest.strip_prefix('"') {
            let end = stripped.find('"').unwrap_or(stripped.len());
            let v = stripped[..end].to_owned();
            rest = stripped.get(end + 1..).unwrap_or("");
            v
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            let v = rest[..end].trim().to_owned();
            rest = rest.get(end..).unwrap_or("");
            v
        };
        if !key.is_empty() {
            out.push((key, value));
        }
    }
    out
}

/// Credentials + request context for computing the response.
#[derive(Debug, Clone)]
pub struct Credentials<'a> {
    /// Digest username.
    pub username: &'a str,
    /// Digest password.
    pub password: &'a str,
    /// Request method (`REGISTER`, `INVITE`, ...).
    pub method: &'a str,
    /// Request URI (the digest URI, usually the request line URI).
    pub uri: &'a str,
    /// Client nonce (random; caller supplies for determinism/testing).
    pub cnonce: &'a str,
    /// Nonce count, 1-based.
    pub nc: u32,
}

/// Compute the digest `response` parameter value.
#[must_use]
pub fn digest_response(ch: &Challenge, cred: &Credentials<'_>) -> String {
    let ha1 = ch
        .algorithm
        .hash(&format!("{}:{}:{}", cred.username, ch.realm, cred.password));
    let ha2 = ch.algorithm.hash(&format!("{}:{}", cred.method, cred.uri));
    if ch.qop_auth {
        ch.algorithm.hash(&format!(
            "{ha1}:{}:{:08x}:{}:auth:{ha2}",
            ch.nonce, cred.nc, cred.cnonce
        ))
    } else {
        ch.algorithm.hash(&format!("{ha1}:{}:{ha2}", ch.nonce))
    }
}

/// Build the complete authorization header LINE (name + value, no CRLF):
/// `Authorization: Digest ...` or `Proxy-Authorization: Digest ...`.
#[must_use]
pub fn authorization_header(ch: &Challenge, cred: &Credentials<'_>) -> String {
    let response = digest_response(ch, cred);
    let name = if ch.proxy {
        "Proxy-Authorization"
    } else {
        "Authorization"
    };
    let mut v = format!(
        "{name}: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", \
         response=\"{response}\", algorithm={}",
        cred.username,
        ch.realm,
        ch.nonce,
        cred.uri,
        ch.algorithm.token(),
    );
    if ch.qop_auth {
        v.push_str(&format!(
            ", qop=auth, cnonce=\"{}\", nc={:08x}",
            cred.cnonce, cred.nc
        ));
    }
    if let Some(opaque) = &ch.opaque {
        v.push_str(&format!(", opaque=\"{opaque}\""));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2617 §3.5: the canonical MD5 example.
    #[test]
    fn rfc2617_md5_example() {
        let ch = parse_challenge(
            r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#,
            false,
        )
        .expect("parses");
        assert_eq!(ch.realm, "testrealm@host.com");
        assert!(ch.qop_auth);
        let cred = Credentials {
            username: "Mufasa",
            password: "Circle Of Life",
            method: "GET",
            uri: "/dir/index.html",
            cnonce: "0a4f113b",
            nc: 1,
        };
        assert_eq!(
            digest_response(&ch, &cred),
            "6629fae49393a05397450978507c4ef1"
        );
        let header = authorization_header(&ch, &cred);
        assert!(header.starts_with("Authorization: Digest username=\"Mufasa\""));
        assert!(header.contains("nc=00000001"), "{header}");
        assert!(header.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
    }

    /// RFC 7616 §3.9.1: the SHA-256 example.
    #[test]
    fn rfc7616_sha256_example() {
        let ch = parse_challenge(
            r#"Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#,
            false,
        )
        .expect("parses");
        assert_eq!(ch.algorithm, Algorithm::Sha256);
        let cred = Credentials {
            username: "Mufasa",
            password: "Circle of Life",
            method: "GET",
            uri: "/dir/index.html",
            cnonce: "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
            nc: 1,
        };
        assert_eq!(
            digest_response(&ch, &cred),
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
        );
    }

    #[test]
    fn no_qop_legacy_response() {
        // RFC 2069 style (no qop): response = H(HA1:nonce:HA2).
        let ch = Challenge {
            realm: "r".into(),
            nonce: "n".into(),
            opaque: None,
            algorithm: Algorithm::Md5,
            qop_auth: false,
            stale: false,
            proxy: false,
        };
        let cred = Credentials {
            username: "u",
            password: "p",
            method: "REGISTER",
            uri: "sip:example.org",
            cnonce: "x",
            nc: 1,
        };
        let ha1 = md5_hex(b"u:r:p");
        let ha2 = md5_hex(b"REGISTER:sip:example.org");
        let expected = md5_hex(format!("{ha1}:n:{ha2}").as_bytes());
        assert_eq!(digest_response(&ch, &cred), expected);
        let header = authorization_header(&ch, &cred);
        assert!(!header.contains("qop"), "{header}");
        assert!(!header.contains("cnonce"), "{header}");
    }

    #[test]
    fn proxy_and_stale_flags() {
        let ch =
            parse_challenge(r#"Digest realm="r", nonce="new", stale=true"#, true).expect("parses");
        assert!(ch.stale);
        assert!(ch.proxy);
        let cred = Credentials {
            username: "u",
            password: "p",
            method: "INVITE",
            uri: "sip:x",
            cnonce: "c",
            nc: 2,
        };
        assert!(authorization_header(&ch, &cred).starts_with("Proxy-Authorization: Digest"));
    }

    #[test]
    fn rejects_non_digest_and_incomplete() {
        assert!(parse_challenge("Basic realm=\"x\"", false).is_none());
        assert!(
            parse_challenge("Digest nonce=\"n\"", false).is_none(),
            "no realm"
        );
        assert!(
            parse_challenge("Digest realm=\"r\"", false).is_none(),
            "no nonce"
        );
    }
}
