//! SRTP (RFC 3711) with SDES keying (RFC 4568), the shape SIPp's `JLSRTP`
//! implements: AES-CM-128 or the NULL cipher, HMAC-SHA1 with an 80- or
//! 32-bit tag, a 16-byte master key + 14-byte salt carried base64 in
//! `a=crypto:… inline:…`, key derivation rate 0, no MKI, no replay list,
//! no SRTCP. Payload-only encryption after a fixed 12-byte header (no
//! CSRC/extension parsing), exactly as SIPp.
//!
//! One deliberate difference: SIPp authenticates with the rollover counter
//! from *before* the packet's own rollover (its tag is issued before
//! `_ROC` is updated), so its packets are rejected by conforming stacks
//! after sequence number 65535. sipr uses the estimated ROC of the packet
//! being processed, per RFC 3711 §4.2, and documents this in SIPP_COMPAT.

use sipr_auth::srtp_kdf::{SessionKeys, aes_cm_apply, derive_session_keys, packet_iv};
use sipr_auth::{base64, hmac_sha1};

/// The RTP header size SRTP protects as-is.
pub const HEADER_LEN: usize = 12;
/// Master key length (all suites).
pub const MASTER_KEY_LEN: usize = 16;
/// Master salt length (all suites).
pub const MASTER_SALT_LEN: usize = 14;

/// The four suites SIPp's `getCryptoSuite()` can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// `AES_CM_128_HMAC_SHA1_80`
    AesCm128HmacSha180,
    /// `AES_CM_128_HMAC_SHA1_32`
    AesCm128HmacSha132,
    /// `NULL_HMAC_SHA1_80`
    NullHmacSha180,
    /// `NULL_HMAC_SHA1_32`
    NullHmacSha132,
}

impl Suite {
    /// Parse the SDP suite name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "AES_CM_128_HMAC_SHA1_80" => Some(Self::AesCm128HmacSha180),
            "AES_CM_128_HMAC_SHA1_32" => Some(Self::AesCm128HmacSha132),
            "NULL_HMAC_SHA1_80" => Some(Self::NullHmacSha180),
            "NULL_HMAC_SHA1_32" => Some(Self::NullHmacSha132),
            _ => None,
        }
    }

    /// The SDP suite name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AesCm128HmacSha180 => "AES_CM_128_HMAC_SHA1_80",
            Self::AesCm128HmacSha132 => "AES_CM_128_HMAC_SHA1_32",
            Self::NullHmacSha180 => "NULL_HMAC_SHA1_80",
            Self::NullHmacSha132 => "NULL_HMAC_SHA1_32",
        }
    }

    /// Authentication tag length in bytes.
    #[must_use]
    pub fn tag_len(self) -> usize {
        match self {
            Self::AesCm128HmacSha180 | Self::NullHmacSha180 => 10,
            Self::AesCm128HmacSha132 | Self::NullHmacSha132 => 4,
        }
    }

    /// Whether the suite encrypts (the NULL cipher only authenticates).
    #[must_use]
    pub fn encrypts(self) -> bool {
        matches!(self, Self::AesCm128HmacSha180 | Self::AesCm128HmacSha132)
    }
}

/// A master key + salt, the SDES `inline:` material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterKey {
    /// 16 bytes.
    pub key: [u8; MASTER_KEY_LEN],
    /// 14 bytes.
    pub salt: [u8; MASTER_SALT_LEN],
}

impl MasterKey {
    /// From 30 random bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 30]) -> Self {
        let mut key = [0u8; 16];
        key.copy_from_slice(&bytes[..16]);
        let mut salt = [0u8; 14];
        salt.copy_from_slice(&bytes[16..]);
        Self { key, salt }
    }

    /// The SDES form: base64(key ‖ salt), 40 characters, no padding (SIPp
    /// emits exactly that).
    #[must_use]
    pub fn to_sdes(&self) -> String {
        let mut bytes = self.key.to_vec();
        bytes.extend_from_slice(&self.salt);
        base64::encode(&bytes).trim_end_matches('=').to_owned()
    }

    /// Parse the `inline:` value (`key||salt[|lifetime][|MKI:len]`); the
    /// lifetime and MKI parts are ignored, as SIPp ignores them.
    #[must_use]
    pub fn from_sdes(value: &str) -> Option<Self> {
        let b64 = value.split('|').next()?;
        let bytes = base64::decode(b64)?;
        if bytes.len() < 30 {
            return None;
        }
        let mut raw = [0u8; 30];
        raw.copy_from_slice(&bytes[..30]);
        Some(Self::from_bytes(&raw))
    }
}

/// Why a packet could not be unprotected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrtpError {
    /// Shorter than a header plus the tag.
    TooShort,
    /// The authentication tag did not verify.
    AuthFailed,
}

impl std::fmt::Display for SrtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "SRTP packet too short"),
            Self::AuthFailed => write!(f, "SRTP authentication failed"),
        }
    }
}

/// One direction of an SRTP stream.
#[derive(Debug, Clone)]
pub struct SrtpContext {
    suite: Suite,
    keys: SessionKeys,
    /// False for the NULL cipher and for `UNENCRYPTED_SRTP`.
    encrypt: bool,
    roc: u32,
    /// Highest sequence number seen (`s_l`), once one has been.
    s_l: Option<u16>,
}

impl SrtpContext {
    /// A context for `suite` under `master`. `unencrypted` is the
    /// `UNENCRYPTED_SRTP` session parameter: authenticate only, whatever
    /// the suite says (SIPp's `ue…` keywords).
    #[must_use]
    pub fn new(suite: Suite, master: &MasterKey, unencrypted: bool) -> Self {
        Self {
            suite,
            keys: derive_session_keys(&master.key, &master.salt),
            encrypt: suite.encrypts() && !unencrypted,
            roc: 0,
            s_l: None,
        }
    }

    /// The suite.
    #[must_use]
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// RFC 3711 §3.3.1: the ROC the packet with sequence `seq` belongs to.
    fn estimate_roc(&self, seq: u16) -> u32 {
        let Some(s_l) = self.s_l else {
            return self.roc;
        };
        let diff = i32::from(seq) - i32::from(s_l);
        if s_l < 32_768 {
            if diff > 32_768 {
                self.roc.wrapping_sub(1)
            } else {
                self.roc
            }
        } else if diff < -32_768 {
            self.roc.wrapping_add(1)
        } else {
            self.roc
        }
    }

    fn advance(&mut self, v: u32, seq: u16) {
        // s_l tracks the highest index seen (RFC 3711 §3.3.1).
        let newer = match self.s_l {
            None => true,
            Some(s_l) => {
                let (iv, il) = (
                    (u64::from(v) << 16) | u64::from(seq),
                    (u64::from(self.roc) << 16) | u64::from(s_l),
                );
                iv > il
            }
        };
        if newer {
            self.roc = v;
            self.s_l = Some(seq);
        }
    }

    /// Turn an RTP packet into an SRTP packet: encrypt the payload (unless
    /// NULL/unencrypted) and append the tag over header ‖ ciphertext ‖ ROC.
    /// Packets shorter than a header are returned unchanged.
    #[must_use]
    pub fn protect(&mut self, rtp: &[u8]) -> Vec<u8> {
        if rtp.len() < HEADER_LEN {
            return rtp.to_vec();
        }
        let seq = u16::from_be_bytes([rtp[2], rtp[3]]);
        let ssrc = u32::from_be_bytes([rtp[8], rtp[9], rtp[10], rtp[11]]);
        let v = self.estimate_roc(seq);
        let index = (u64::from(v) << 16) | u64::from(seq);
        let mut out = rtp.to_vec();
        if self.encrypt {
            let iv = packet_iv(&self.keys.salt, ssrc, index);
            aes_cm_apply(&self.keys.cipher_key, &iv, &mut out[HEADER_LEN..]);
        }
        let tag = self.tag(&out, v);
        out.extend_from_slice(&tag);
        self.advance(v, seq);
        out
    }

    /// Verify and strip the tag, then decrypt the payload.
    ///
    /// # Errors
    ///
    /// [`SrtpError`] for a short packet or a tag that does not verify.
    pub fn unprotect(&mut self, srtp: &[u8]) -> Result<Vec<u8>, SrtpError> {
        let tag_len = self.suite.tag_len();
        if srtp.len() < HEADER_LEN + tag_len {
            return Err(SrtpError::TooShort);
        }
        let (body, tag) = srtp.split_at(srtp.len() - tag_len);
        let seq = u16::from_be_bytes([body[2], body[3]]);
        let ssrc = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
        let v = self.estimate_roc(seq);
        let expected = self.tag(body, v);
        // Not constant-time, like SIPp's vector compare; this is a test tool.
        if expected != tag {
            return Err(SrtpError::AuthFailed);
        }
        let mut out = body.to_vec();
        if self.encrypt {
            let index = (u64::from(v) << 16) | u64::from(seq);
            let iv = packet_iv(&self.keys.salt, ssrc, index);
            aes_cm_apply(&self.keys.cipher_key, &iv, &mut out[HEADER_LEN..]);
        }
        self.advance(v, seq);
        Ok(out)
    }

    fn tag(&self, authenticated: &[u8], roc: u32) -> Vec<u8> {
        let mut data = authenticated.to_vec();
        data.extend_from_slice(&roc.to_be_bytes());
        hmac_sha1(&self.keys.auth_key, &data)[..self.suite.tag_len()].to_vec()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn master() -> MasterKey {
        let mut raw = [0u8; 30];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        MasterKey::from_bytes(&raw)
    }

    fn rtp(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, 0x08];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&1000u32.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn sdes_round_trips_and_tolerates_suffixes() {
        let m = master();
        let s = m.to_sdes();
        assert_eq!(s.len(), 40);
        assert!(!s.contains('='));
        assert_eq!(MasterKey::from_sdes(&s).unwrap(), m);
        assert_eq!(MasterKey::from_sdes(&format!("{s}|2^20|1:4")).unwrap(), m);
        assert!(MasterKey::from_sdes("short").is_none());
        assert!(MasterKey::from_sdes("!!!!").is_none());
    }

    #[test]
    fn protect_then_unprotect_for_every_suite() {
        for suite in [
            Suite::AesCm128HmacSha180,
            Suite::AesCm128HmacSha132,
            Suite::NullHmacSha180,
            Suite::NullHmacSha132,
        ] {
            let mut tx = SrtpContext::new(suite, &master(), false);
            let mut rx = SrtpContext::new(suite, &master(), false);
            for seq in [0u16, 1, 2, 500] {
                let plain = rtp(seq, 0xdead_beef, b"sixteen byte pay");
                let wire = tx.protect(&plain);
                assert_eq!(wire.len(), plain.len() + suite.tag_len());
                assert_eq!(&wire[..12], &plain[..12], "header is clear");
                if suite.encrypts() {
                    assert_ne!(&wire[12..28], &plain[12..], "{suite:?} encrypts");
                } else {
                    assert_eq!(&wire[12..28], &plain[12..], "{suite:?} does not encrypt");
                }
                assert_eq!(rx.unprotect(&wire).unwrap(), plain, "{suite:?} seq {seq}");
            }
            assert_eq!(Suite::parse(suite.as_str()), Some(suite));
        }
    }

    #[test]
    fn unencrypted_srtp_only_authenticates() {
        let mut tx = SrtpContext::new(Suite::AesCm128HmacSha180, &master(), true);
        let plain = rtp(7, 1, b"clear");
        let wire = tx.protect(&plain);
        assert_eq!(&wire[..plain.len()], &plain[..]);
        let mut rx = SrtpContext::new(Suite::AesCm128HmacSha180, &master(), true);
        assert_eq!(rx.unprotect(&wire).unwrap(), plain);
    }

    #[test]
    fn tampering_or_wrong_key_fails_auth() {
        let mut tx = SrtpContext::new(Suite::AesCm128HmacSha180, &master(), false);
        let wire = tx.protect(&rtp(1, 1, b"payload!"));
        let mut rx = SrtpContext::new(Suite::AesCm128HmacSha180, &master(), false);
        let mut bad = wire.clone();
        bad[15] ^= 1;
        assert_eq!(rx.unprotect(&bad), Err(SrtpError::AuthFailed));
        let mut other = [0u8; 30];
        other[0] = 1;
        let mut rx2 = SrtpContext::new(
            Suite::AesCm128HmacSha180,
            &MasterKey::from_bytes(&other),
            false,
        );
        assert_eq!(rx2.unprotect(&wire), Err(SrtpError::AuthFailed));
        assert_eq!(rx.unprotect(&wire[..8]), Err(SrtpError::TooShort));
    }

    #[test]
    fn rollover_uses_the_new_roc_in_iv_and_tag() {
        let mut tx = SrtpContext::new(Suite::AesCm128HmacSha180, &master(), false);
        let mut rx = SrtpContext::new(Suite::AesCm128HmacSha180, &master(), false);
        for seq in [65_530u16, 65_535, 0, 1] {
            let plain = rtp(seq, 42, b"rollover payload");
            let wire = tx.protect(&plain);
            assert_eq!(rx.unprotect(&wire).unwrap(), plain, "seq {seq}");
        }
        assert_eq!(tx.roc, 1);
        assert_eq!(rx.roc, 1);
        // A late packet from before the rollover still verifies (ROC-1).
        let mut tx_late = SrtpContext::new(Suite::AesCm128HmacSha180, &master(), false);
        tx_late.roc = 0;
        tx_late.s_l = Some(65_534);
        let wire = tx_late.protect(&rtp(65_534, 42, b"late"));
        assert_eq!(rx.unprotect(&wire).unwrap(), rtp(65_534, 42, b"late"));
    }
}
