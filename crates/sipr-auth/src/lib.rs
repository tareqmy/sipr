//! `sipr-auth`: digest authentication (RFC 2617 / RFC 7616) and IMS AKA
//! (RFC 3310 `AKAv1-MD5`, 3GPP Milenage) backing the `[authentication]`
//! keyword (milestones M6 and M16).
//!
//! Flow: a `<recv auth="true">` on a 401/407 stores the parsed
//! [`Challenge`]; the next send's `[authentication]` keyword calls
//! [`authorization_header`] to produce the full `Authorization:` /
//! `Proxy-Authorization:` line. MD5 and SHA-256 with `qop="auth"` are
//! supported; for `AKAv1-MD5` the nonce carries RAND‖AUTN, Milenage
//! yields RES, and RES's raw bytes are the digest password. All primitives
//! (MD5, SHA-256, AES-128, Milenage, base64) are in-tree.

mod aes;
pub mod base64;
mod hash;
pub mod milenage;

pub use hash::{hmac_sha1, md5_hex, sha1, sha256_hex};
pub mod srtp_kdf;
pub use aes::encrypt_block as aes128_encrypt_block;

/// Which digest algorithm the challenge requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// `MD5` (RFC 2617 default).
    #[default]
    Md5,
    /// `SHA-256` (RFC 7616).
    Sha256,
    /// `AKAv1-MD5` (RFC 3310): MD5 digest whose password is the Milenage
    /// RES computed from the nonce's RAND/AUTN.
    AkaV1Md5,
}

impl Algorithm {
    fn hash(self, data: &[u8]) -> String {
        match self {
            Self::Md5 | Self::AkaV1Md5 => md5_hex(data),
            Self::Sha256 => sha256_hex(data),
        }
    }

    fn token(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha256 => "SHA-256",
            Self::AkaV1Md5 => "AKAv1-MD5",
        }
    }
}

/// The subscriber's AKA secrets (`aka_K`, `aka_OP`/`aka_OPc`, `aka_AMF`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaKeys {
    /// The 128-bit subscriber key K.
    pub k: [u8; 16],
    /// The operator variant OPc (derived from OP when `aka_OP` is given).
    pub opc: [u8; 16],
    /// The AMF to compute XMAC with; `None` = the AMF carried in AUTN.
    /// SIPp always uses its configured `aka_AMF` and ignores AUTN's.
    pub amf: Option<[u8; 2]>,
    /// The client's highest accepted sequence number SQN_MS (`aka_sqn=`).
    /// When set, a challenge whose SQN is not greater triggers
    /// resynchronisation (TS 33.102 §6.3.3); `None` accepts any SQN.
    pub sqn_ms: Option<[u8; 6]>,
    /// `aka_resync=1`: resynchronise on every challenge regardless of SQN,
    /// to exercise a server's AUTS handling.
    pub force_resync: bool,
}

/// Why an authorization header could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// `verifyauth`: the credential is not a Digest one.
    NotDigest,
    /// `verifyauth`: an algorithm other than MD5 / SHA-256.
    UnsupportedAlgorithm(String),
    /// The challenge is `AKAv1-MD5` but no `aka_K`/`aka_OP` were given.
    AkaKeysMissing,
    /// The nonce is not base64 or decodes to fewer than 32 bytes.
    AkaNonceMalformed,
    /// The MAC in AUTN does not match XMAC: the server does not know the
    /// secret (or a different AMF is in play). SIPp aborts the process
    /// here; sipr fails the call.
    AkaMacMismatch,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDigest => write!(f, "authentication must be Digest"),
            Self::UnsupportedAlgorithm(algo) => write!(
                f,
                "authentication must use MD5 or SHA-256, value is '{algo}'"
            ),
            Self::AkaKeysMissing => write!(
                f,
                "AKAv1-MD5 challenge but no AKA keys: give aka_K= and aka_OP= (or aka_OPc=) \
                 in [authentication ...]"
            ),
            Self::AkaNonceMalformed => write!(
                f,
                "AKAv1-MD5 nonce is not base64(RAND || AUTN) (need at least 32 decoded bytes)"
            ),
            Self::AkaMacMismatch => write!(
                f,
                "AKA MAC != XMAC — the server does not know the secret (or a different AMF)"
            ),
        }
    }
}

impl std::error::Error for AuthError {}

/// What running Milenage over an AKA challenge yielded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaResult {
    /// The Milenage outputs (RES, CK, IK, AK).
    pub vector: milenage::AkaVector,
    /// The sequence number recovered from AUTN (`SQN ⊕ AK ⊕ AK`).
    pub sqn: [u8; 6],
    /// The AMF carried in AUTN.
    pub amf: [u8; 2],
    /// Set when the client must resynchronise (RFC 3310 §3.2): the 14-byte
    /// AUTS = (SQN_MS ⊕ AK*) ‖ MAC-S, to send base64 in `auts=` with an
    /// empty-password digest.
    pub auts: Option<[u8; 14]>,
}

/// Run AKA over the challenge nonce: decode RAND‖AUTN, compute RES/CK/IK/AK,
/// recover SQN, and verify AUTN's MAC against f1 (XMAC).
///
/// # Errors
///
/// [`AuthError::AkaNonceMalformed`] or [`AuthError::AkaMacMismatch`].
pub fn aka_challenge_response(nonce: &str, keys: &AkaKeys) -> Result<AkaResult, AuthError> {
    let bytes = base64::decode(nonce).ok_or(AuthError::AkaNonceMalformed)?;
    if bytes.len() < 32 {
        return Err(AuthError::AkaNonceMalformed);
    }
    let mut rand = [0u8; 16];
    rand.copy_from_slice(&bytes[0..16]);
    let mut sqn_ak = [0u8; 6];
    sqn_ak.copy_from_slice(&bytes[16..22]);
    let mut amf = [0u8; 2];
    amf.copy_from_slice(&bytes[22..24]);
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&bytes[24..32]);
    let vector = milenage::f2345(&keys.k, &keys.opc, &rand);
    let mut sqn = [0u8; 6];
    for i in 0..6 {
        sqn[i] = sqn_ak[i] ^ vector.ak[i];
    }
    let xmac_amf = keys.amf.unwrap_or(amf);
    let xmac = milenage::f1(&keys.k, &keys.opc, &rand, &sqn, &xmac_amf);
    if xmac != mac {
        return Err(AuthError::AkaMacMismatch);
    }
    // Sequence-number check (TS 33.102 §6.3.3, simplified to "must be
    // greater than SQN_MS"): out of range, or forced, → AUTS.
    let sqn_ms = keys.sqn_ms;
    let out_of_range = sqn_ms.is_some_and(|ms| sqn_value(&sqn) <= sqn_value(&ms));
    let auts = if keys.force_resync || out_of_range {
        let ms = sqn_ms.unwrap_or(sqn);
        let ak_star = milenage::f5_star(&keys.k, &keys.opc, &rand);
        // AMF* is all zeros for resynchronisation (TS 33.102 §6.3.3).
        let mac_s = milenage::f1_star(&keys.k, &keys.opc, &rand, &ms, &[0, 0]);
        let mut auts = [0u8; 14];
        for i in 0..6 {
            auts[i] = ms[i] ^ ak_star[i];
        }
        auts[6..14].copy_from_slice(&mac_s);
        Some(auts)
    } else {
        None
    };
    Ok(AkaResult {
        vector,
        sqn,
        amf,
        auts,
    })
}

/// A 48-bit SQN as an integer, for ordering.
fn sqn_value(sqn: &[u8; 6]) -> u64 {
    sqn.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
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
                // SIPp matches by case-insensitive prefix (MD5-sess → MD5,
                // AKAv2-MD5 is rejected there; here it is an error at use).
                let upper = val.to_ascii_uppercase();
                algorithm = if upper.starts_with("SHA-256") {
                    Algorithm::Sha256
                } else if upper.starts_with("AKAV1-MD5") {
                    Algorithm::AkaV1Md5
                } else {
                    Algorithm::Md5 // MD5, MD5-sess (treated as MD5)
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
    /// AKA secrets, required when the challenge is `AKAv1-MD5`.
    pub aka: Option<AkaKeys>,
}

/// Compute the digest `response` parameter value.
///
/// # Errors
///
/// [`AuthError`] for an `AKAv1-MD5` challenge whose keys are missing, whose
/// nonce is malformed, or whose MAC does not verify.
pub fn digest_response(ch: &Challenge, cred: &Credentials<'_>) -> Result<String, AuthError> {
    let (password, _auts) = resolve_password(ch, cred)?;
    Ok(response_for(ch, cred, &password))
}

/// The digest password: the configured string, or for AKA the raw RES
/// bytes (RFC 3310 §3; SIPp passes RESLEN=8 explicitly so NUL bytes
/// survive) — or an empty password plus the base64 AUTS when the client
/// must resynchronise (RFC 3310 §3.2).
fn resolve_password(
    ch: &Challenge,
    cred: &Credentials<'_>,
) -> Result<(Vec<u8>, Option<String>), AuthError> {
    if ch.algorithm != Algorithm::AkaV1Md5 {
        return Ok((cred.password.as_bytes().to_vec(), None));
    }
    let keys = cred.aka.as_ref().ok_or(AuthError::AkaKeysMissing)?;
    let result = aka_challenge_response(&ch.nonce, keys)?;
    Ok(match result.auts {
        Some(auts) => (Vec::new(), Some(base64::encode(&auts))),
        None => (result.vector.res.to_vec(), None),
    })
}

/// The `response` value for a given password.
fn response_for(ch: &Challenge, cred: &Credentials<'_>, password: &[u8]) -> String {
    let mut a1 = format!("{}:{}:", cred.username, ch.realm).into_bytes();
    a1.extend_from_slice(password);
    let ha1 = ch.algorithm.hash(&a1);
    let ha2 = ch
        .algorithm
        .hash(format!("{}:{}", cred.method, cred.uri).as_bytes());
    if ch.qop_auth {
        ch.algorithm.hash(
            format!(
                "{ha1}:{}:{:08x}:{}:auth:{ha2}",
                ch.nonce, cred.nc, cred.cnonce
            )
            .as_bytes(),
        )
    } else {
        ch.algorithm
            .hash(format!("{ha1}:{}:{ha2}", ch.nonce).as_bytes())
    }
}

/// Build the complete authorization header LINE (name + value, no CRLF):
/// `Authorization: Digest ...` or `Proxy-Authorization: Digest ...`.
///
/// # Errors
///
/// As [`digest_response`].
pub fn authorization_header(ch: &Challenge, cred: &Credentials<'_>) -> Result<String, AuthError> {
    let (password, auts) = resolve_password(ch, cred)?;
    let response = response_for(ch, cred, &password);
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
    if let Some(auts) = auts {
        v.push_str(&format!(", auts=\"{auts}\""));
    }
    Ok(v)
}

/// `<verifyauth>`: check a request's `Authorization:` value against a known
/// username and password, the way SIPp's `verifyAuthHeader` does — the
/// digest parameters (`realm`, `uri`, `nonce`, `cnonce`, `nc`, `qop`,
/// `algorithm`, `response`) are all taken from the header the client sent,
/// so only the shared secret is checked, not the server's own challenge.
///
/// `method` is the request method; `body` is the message body for
/// `qop=auth-int`; `auth_uri` is the `-auth_uri` override, which SIPp
/// applies to the verifier's HA2 as well (`sip:<auth_uri>`).
///
/// # Errors
///
/// [`AuthError::NotDigest`] when the header is not a Digest credential, and
/// [`AuthError::UnsupportedAlgorithm`] for anything but MD5 / SHA-256 — the
/// two cases SIPp warns about and treats as "not verified".
pub fn verify_authorization(
    header_value: &str,
    username: &str,
    password: &str,
    method: &str,
    body: &[u8],
    auth_uri: Option<&str>,
) -> Result<bool, AuthError> {
    let rest = header_value.trim();
    let Some(rest) = strip_prefix_ignore_case(rest, "Digest") else {
        return Err(AuthError::NotDigest);
    };
    let params = parse_params(rest);
    let param = |name: &str| -> String {
        params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let algo = param("algorithm");
    let algorithm = if algo.is_empty() || algo.len() >= 3 && algo[..3].eq_ignore_ascii_case("MD5") {
        Algorithm::Md5
    } else if algo.len() >= 7 && algo[..7].eq_ignore_ascii_case("SHA-256") {
        Algorithm::Sha256
    } else {
        return Err(AuthError::UnsupportedAlgorithm(algo));
    };
    let uri = match auth_uri {
        Some(u) => format!("sip:{u}"),
        None => param("uri"),
    };
    let qop = param("qop");
    let cnonce = param("cnonce");
    let ha1 = algorithm.hash(format!("{username}:{}:{password}", param("realm")).as_bytes());
    let ha2 = if qop.to_ascii_lowercase().contains("auth-int") {
        let body_hash = algorithm.hash(body);
        algorithm.hash(format!("{method}:{uri}:{body_hash}").as_bytes())
    } else {
        algorithm.hash(format!("{method}:{uri}").as_bytes())
    };
    // SIPp keys the qop form on cnonce being present, not on qop.
    let expected = if cnonce.is_empty() {
        algorithm.hash(format!("{ha1}:{}:{ha2}", param("nonce")).as_bytes())
    } else {
        algorithm.hash(
            format!(
                "{ha1}:{}:{}:{cnonce}:{qop}:{ha2}",
                param("nonce"),
                param("nc")
            )
            .as_bytes(),
        )
    };
    Ok(expected.eq_ignore_ascii_case(&param("response")))
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
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
            aka: None,
        };
        assert_eq!(
            digest_response(&ch, &cred).unwrap(),
            "6629fae49393a05397450978507c4ef1"
        );
        let header = authorization_header(&ch, &cred).unwrap();
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
            aka: None,
        };
        assert_eq!(
            digest_response(&ch, &cred).unwrap(),
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
            aka: None,
        };
        let ha1 = md5_hex(b"u:r:p");
        let ha2 = md5_hex(b"REGISTER:sip:example.org");
        let expected = md5_hex(format!("{ha1}:n:{ha2}").as_bytes());
        assert_eq!(digest_response(&ch, &cred).unwrap(), expected);
        let header = authorization_header(&ch, &cred).unwrap();
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
            aka: None,
        };
        assert!(
            authorization_header(&ch, &cred)
                .unwrap()
                .starts_with("Proxy-Authorization: Digest")
        );
    }

    /// AKAv1-MD5 end to end over TS 35.208 Test Set 1: the nonce is
    /// base64(RAND || SQN⊕AK || AMF || MAC-A), the password is RES.
    #[test]
    fn akav1_md5_over_test_set_1() {
        fn hex<const N: usize>(s: &str) -> [u8; N] {
            let mut out = [0u8; N];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        }
        let k = hex::<16>("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = hex::<16>("cdc202d5123e20f62b6d676ac72cb318");
        let keys = AkaKeys {
            k,
            opc: milenage::opc(&k, &op),
            amf: None,
            sqn_ms: None,
            force_resync: false,
        };
        let rand = hex::<16>("23553cbe9637a89d218ae64dae47bf35");
        let sqn = hex::<6>("ff9bb4d0b607");
        let amf = hex::<2>("b9b9");
        let ak = hex::<6>("aa689c648370");
        let mut autn = Vec::new();
        for i in 0..6 {
            autn.push(sqn[i] ^ ak[i]);
        }
        autn.extend_from_slice(&amf);
        autn.extend_from_slice(&hex::<8>("4a9ffac354dfafb3"));
        let mut nonce_bytes = rand.to_vec();
        nonce_bytes.extend_from_slice(&autn);
        let nonce = base64::encode(&nonce_bytes);
        let ch = parse_challenge(
            &format!(r#"Digest realm="ims.mnc001.mcc001.3gppnetwork.org", nonce="{nonce}", algorithm=AKAv1-MD5, qop="auth""#),
            false,
        )
        .unwrap();
        assert_eq!(ch.algorithm, Algorithm::AkaV1Md5);
        let r = aka_challenge_response(&nonce, &keys).unwrap();
        assert_eq!(r.sqn, sqn);
        assert_eq!(r.amf, amf);
        assert_eq!(r.vector.res, hex::<8>("a54211d5e3ba50bf"));
        let cred = Credentials {
            username: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
            password: "ignored",
            method: "REGISTER",
            uri: "sip:ims.mnc001.mcc001.3gppnetwork.org",
            cnonce: "abcd",
            nc: 1,
            aka: Some(keys.clone()),
        };
        // Expected: plain MD5 digest with the 8 RES bytes as the password.
        let mut a1 =
            b"001010123456789@ims.mnc001.mcc001.3gppnetwork.org:ims.mnc001.mcc001.3gppnetwork.org:"
                .to_vec();
        a1.extend_from_slice(&hex::<8>("a54211d5e3ba50bf"));
        let ha1 = md5_hex(&a1);
        let ha2 = md5_hex(b"REGISTER:sip:ims.mnc001.mcc001.3gppnetwork.org");
        let expected = md5_hex(format!("{ha1}:{nonce}:00000001:abcd:auth:{ha2}").as_bytes());
        assert_eq!(digest_response(&ch, &cred).unwrap(), expected);
        let header = authorization_header(&ch, &cred).unwrap();
        assert!(header.contains("algorithm=AKAv1-MD5"), "{header}");
        // A configured AMF that differs from AUTN's breaks the MAC (SIPp's
        // behavior when aka_AMF is wrong).
        let wrong = AkaKeys {
            amf: Some([0, 0]),
            ..keys.clone()
        };
        assert_eq!(
            aka_challenge_response(&nonce, &wrong),
            Err(AuthError::AkaMacMismatch)
        );
        // Bad nonces.
        assert_eq!(
            aka_challenge_response("not base64!", &keys),
            Err(AuthError::AkaNonceMalformed)
        );
        assert_eq!(
            aka_challenge_response(&base64::encode(&[0u8; 31]), &keys),
            Err(AuthError::AkaNonceMalformed)
        );
        // No keys.
        let no_keys = Credentials { aka: None, ..cred };
        assert_eq!(
            digest_response(&ch, &no_keys),
            Err(AuthError::AkaKeysMissing)
        );
    }

    /// Resynchronisation (RFC 3310 §3.2 / TS 33.102 §6.3.3): a challenge
    /// whose SQN is not above the client's SQN_MS yields AUTS and an
    /// empty-password digest; a forced resync does so regardless.
    #[test]
    fn akav1_resync_emits_auts_with_an_empty_password() {
        fn hex<const N: usize>(s: &str) -> [u8; N] {
            let mut out = [0u8; N];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        }
        let k = hex::<16>("465b5ce8b199b49faa5f0a2ee238a6bc");
        let opc = milenage::opc(&k, &hex::<16>("cdc202d5123e20f62b6d676ac72cb318"));
        let rand = hex::<16>("23553cbe9637a89d218ae64dae47bf35");
        let sqn = hex::<6>("ff9bb4d0b607");
        let amf = hex::<2>("b9b9");
        let ak = hex::<6>("aa689c648370");
        let mut nonce_bytes = rand.to_vec();
        nonce_bytes.extend(sqn.iter().zip(&ak).map(|(s, a)| s ^ a));
        nonce_bytes.extend_from_slice(&amf);
        nonce_bytes.extend_from_slice(&hex::<8>("4a9ffac354dfafb3"));
        let nonce = base64::encode(&nonce_bytes);
        let base = AkaKeys {
            k,
            opc,
            amf: None,
            sqn_ms: None,
            force_resync: false,
        };
        // SQN_MS below the challenge's SQN: accepted, no AUTS.
        let ok = AkaKeys {
            sqn_ms: Some(hex::<6>("ff9bb4d0b600")),
            ..base.clone()
        };
        assert!(aka_challenge_response(&nonce, &ok).unwrap().auts.is_none());
        // SQN_MS equal to it: out of range → AUTS.
        let stale = AkaKeys {
            sqn_ms: Some(sqn),
            ..base.clone()
        };
        let r = aka_challenge_response(&nonce, &stale).unwrap();
        let auts = r.auts.expect("resync");
        let ak_star = hex::<6>("451e8beca43b");
        for i in 0..6 {
            assert_eq!(auts[i] ^ ak_star[i], sqn[i], "SQN_MS ⊕ AK* at {i}");
        }
        assert_eq!(
            &auts[6..14],
            &milenage::f1_star(&k, &opc, &rand, &sqn, &[0, 0])
        );
        // Header: auts present, response computed with an empty password.
        let ch = parse_challenge(
            &format!(r#"Digest realm="ims", nonce="{nonce}", algorithm=AKAv1-MD5, qop="auth""#),
            false,
        )
        .unwrap();
        let cred = Credentials {
            username: "u",
            password: "ignored",
            method: "REGISTER",
            uri: "sip:ims",
            cnonce: "c",
            nc: 1,
            aka: Some(stale),
        };
        let header = authorization_header(&ch, &cred).unwrap();
        assert!(
            header.contains(&format!("auts=\"{}\"", base64::encode(&auts))),
            "{header}"
        );
        let ha1 = md5_hex(b"u:ims:");
        let ha2 = md5_hex(b"REGISTER:sip:ims");
        let expected = md5_hex(format!("{ha1}:{nonce}:00000001:c:auth:{ha2}").as_bytes());
        assert!(
            header.contains(&format!("response=\"{expected}\"")),
            "{header}"
        );
        // Forced resync without an SQN_MS uses the challenge's own SQN.
        let forced = AkaKeys {
            force_resync: true,
            ..base
        };
        let r = aka_challenge_response(&nonce, &forced).unwrap();
        assert!(r.auts.is_some());
        assert_eq!(&r.auts.unwrap()[0..6], &auts[0..6]);
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

    /// SIPp's own `DigestAuth.BasicVerification` vectors (auth.cpp gtests):
    /// the header its `createAuthHeader` built, verified by `verifyAuthHeader`.
    #[test]
    fn verifies_sipps_md5_and_sha256_vectors() {
        let md5 = "Digest username=\"testuser\",realm=\"testrealm@host.com\",\
            uri=\"sip:sip:example.com\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",\
            response=\"db94e01e92f2b09a52a234eeca8b90f7\",algorithm=MD5,\
            opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        assert_eq!(
            verify_authorization(md5, "testuser", "secret", "REGISTER", b"hello world", None),
            Ok(true)
        );
        assert_eq!(
            verify_authorization(md5, "testuser", "wrong", "REGISTER", b"", None),
            Ok(false)
        );
        assert_eq!(
            verify_authorization(md5, "testuser", "secret", "INVITE", b"", None),
            Ok(false)
        );
        let sha = "Digest username=\"testuser\",realm=\"testrealm@host.com\",\
            uri=\"sip:sip:example.com\",nonce=\"ZaGxV2WhsCtREI2EsiD1LR0RYd\",\
            response=\"91b58523b983191b52d14455a2599631990110c974ed2e4b4b49bc6053af04ce\",\
            algorithm=SHA-256";
        assert_eq!(
            verify_authorization(sha, "testuser", "secret", "REGISTER", b"", None),
            Ok(true)
        );
        // Uppercase hex from a client still verifies (SIPp's strcmp would not).
        let upper = sha.replace(
            "91b58523b983191b52d14455a2599631990110c974ed2e4b4b49bc6053af04ce",
            "91B58523B983191B52D14455A2599631990110C974ED2E4B4B49BC6053AF04CE",
        );
        assert_eq!(
            verify_authorization(&upper, "testuser", "secret", "REGISTER", b"", None),
            Ok(true)
        );
    }

    /// What sipr itself sends (qop=auth, and the `-auth_uri` form) verifies.
    #[test]
    fn verifies_sipr_own_qop_header_and_auth_uri_override() {
        let ch = parse_challenge(
            "Digest realm=\"r\", nonce=\"n1\", qop=\"auth\", algorithm=MD5",
            false,
        )
        .expect("challenge");
        let cred = Credentials {
            username: "alice",
            password: "pw",
            method: "INVITE",
            uri: "sip:10.0.0.1:5060",
            cnonce: "abc123",
            nc: 1,
            aka: None,
        };
        let line = authorization_header(&ch, &cred).expect("header");
        let value = line.strip_prefix("Authorization: ").expect("name");
        assert_eq!(
            verify_authorization(value, "alice", "pw", "INVITE", b"", None),
            Ok(true)
        );
        assert_eq!(
            verify_authorization(value, "alice", "pw", "INVITE", b"", Some("other")),
            Ok(false)
        );
        // With -auth_uri the verifier hashes `sip:<auth_uri>` instead of uri=.
        let cred_uri = Credentials {
            uri: "sip:other",
            ..cred
        };
        let line = authorization_header(&ch, &cred_uri).expect("header");
        let value = line.strip_prefix("Authorization: ").expect("name");
        assert_eq!(
            verify_authorization(value, "alice", "pw", "INVITE", b"", Some("other")),
            Ok(true)
        );
    }

    /// `qop=auth-int` hashes the body; cnonce (not qop) selects the RFC 2617 form.
    #[test]
    fn auth_int_and_scheme_errors() {
        let body = b"v=0\r\n";
        let realm = "r";
        let nonce = "n";
        let ha1 = md5_hex(b"bob:r:pw");
        let body_hash = md5_hex(body);
        let ha2 = md5_hex(format!("INVITE:sip:x:{body_hash}").as_bytes());
        let response = md5_hex(format!("{ha1}:{nonce}:00000001:cn:auth-int:{ha2}").as_bytes());
        let header = format!(
            "Digest username=\"bob\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"sip:x\", \
             qop=auth-int, nc=00000001, cnonce=\"cn\", response=\"{response}\""
        );
        assert_eq!(
            verify_authorization(&header, "bob", "pw", "INVITE", body, None),
            Ok(true)
        );
        assert_eq!(
            verify_authorization(&header, "bob", "pw", "INVITE", b"other", None),
            Ok(false)
        );
        assert_eq!(
            verify_authorization("Basic Zm9vOmJhcg==", "bob", "pw", "INVITE", b"", None),
            Err(AuthError::NotDigest)
        );
        assert_eq!(
            verify_authorization(
                "Digest username=\"bob\", algorithm=AKAv1-MD5, response=\"00\"",
                "bob",
                "pw",
                "INVITE",
                b"",
                None
            ),
            Err(AuthError::UnsupportedAlgorithm("AKAv1-MD5".into()))
        );
        // digest is case-insensitive as a scheme token
        assert_eq!(
            verify_authorization(
                "digest username=\"bob\", response=\"00\"",
                "bob",
                "pw",
                "X",
                b"",
                None
            ),
            Ok(false)
        );
    }
}
