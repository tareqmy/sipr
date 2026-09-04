//! SRTP's AES-CM keystream and key derivation (RFC 3711 §4.1.1, §4.3), the
//! cryptography under `sipr-media`'s SRTP transform. Verified against the
//! RFC's Appendix B vectors. AES-128 comes from Milenage's block cipher.

use crate::aes::encrypt_block;

/// The AES-CM keystream: `E_K(IV) || E_K(IV+1) || …`, where `iv` is the
/// 128-bit counter block (the RFC's `(salt * 2^16) XOR (SSRC * 2^64) XOR
/// (index * 2^16)` with a zero low 16-bit block counter). Fills `out`.
pub fn aes_cm_keystream(key: &[u8; 16], iv: &[u8; 16], out: &mut [u8]) {
    let mut counter = *iv;
    for chunk in out.chunks_mut(16) {
        let block = encrypt_block(key, &counter);
        chunk.copy_from_slice(&block[..chunk.len()]);
        // 128-bit big-endian increment (RFC 3711: the low 16 bits count blocks).
        for b in counter.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }
}

/// XOR `data` with the keystream for `iv`: encryption and decryption alike.
pub fn aes_cm_apply(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    let mut ks = vec![0u8; data.len()];
    aes_cm_keystream(key, iv, &mut ks);
    for (d, k) in data.iter_mut().zip(ks) {
        *d ^= k;
    }
}

/// The 128-bit IV for packet index `index` of `ssrc` under `session_salt`
/// (RFC 3711 §4.1.1): `(k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)`.
#[must_use]
pub fn packet_iv(session_salt: &[u8; 14], ssrc: u32, index: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(session_salt);
    for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
        iv[4 + i] ^= b;
    }
    // i * 2^16: the 48-bit index occupies bytes 8..14.
    for (i, b) in index.to_be_bytes()[2..8].iter().enumerate() {
        iv[8 + i] ^= b;
    }
    iv
}

/// The session keys derived from a master key and salt (RFC 3711 §4.3,
/// key derivation rate 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Label 0x00, 128 bits.
    pub cipher_key: [u8; 16],
    /// Label 0x01, 160 bits.
    pub auth_key: [u8; 20],
    /// Label 0x02, 112 bits.
    pub salt: [u8; 14],
}

/// Derive the SRTP session keys: `PRF(master_key, (label || r) XOR master_salt)`
/// with `r = index DIV kdr = 0` — SIPp's `JLSRTP` assumes a zero key
/// derivation rate, and so does this.
#[must_use]
pub fn derive_session_keys(master_key: &[u8; 16], master_salt: &[u8; 14]) -> SessionKeys {
    let mut cipher_key = [0u8; 16];
    prf(master_key, master_salt, 0x00, &mut cipher_key);
    let mut auth_key = [0u8; 20];
    prf(master_key, master_salt, 0x01, &mut auth_key);
    let mut salt = [0u8; 14];
    prf(master_key, master_salt, 0x02, &mut salt);
    SessionKeys {
        cipher_key,
        auth_key,
        salt,
    }
}

/// `PRF_n(master_key, x)` with `x = (label || 0^48) XOR master_salt`, run
/// as AES-CM over a zero plaintext with `x * 2^16` as the IV.
fn prf(master_key: &[u8; 16], master_salt: &[u8; 14], label: u8, out: &mut [u8]) {
    let mut x = *master_salt;
    x[7] ^= label;
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(&x);
    aes_cm_keystream(master_key, &iv, out);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 3711 Appendix B.2: AES-CM keystream.
    #[test]
    fn rfc3711_b2_aes_cm_keystream() {
        let key = hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000");
        let mut ks = [0u8; 48];
        aes_cm_keystream(&key, &iv, &mut ks);
        assert_eq!(to_hex(&ks[0..16]), "e03ead0935c95e80e166b16dd92b4eb4");
        assert_eq!(to_hex(&ks[16..32]), "d23513162b02d0f72a43a2fe4a5f97ab");
        assert_eq!(to_hex(&ks[32..48]), "41e95b3bb0a2e8dd477901e4fca894c0");
        // XOR twice is identity.
        let mut data = b"hello srtp world".to_vec();
        aes_cm_apply(&key, &iv, &mut data);
        assert_ne!(&data[..], b"hello srtp world");
        aes_cm_apply(&key, &iv, &mut data);
        assert_eq!(&data[..], b"hello srtp world");
    }

    /// RFC 3711 Appendix B.3: key derivation.
    #[test]
    fn rfc3711_b3_key_derivation() {
        let master_key = hex::<16>("e1f97a0d3e018be0d64fa32c06de4139");
        let master_salt = hex::<14>("0ec675ad498afeebb6960b3aabe6");
        let k = derive_session_keys(&master_key, &master_salt);
        assert_eq!(to_hex(&k.cipher_key), "c61e7a93744f39ee10734afe3ff7a087");
        assert_eq!(to_hex(&k.salt), "30cbbc08863d8c85d49db34a9ae1");
        assert_eq!(
            to_hex(&k.auth_key),
            "cebe321f6ff7716b6fd4ab49af256a156d38baa4"
        );
    }

    #[test]
    fn packet_iv_layout() {
        let salt = hex::<14>("30cbbc08863d8c85d49db34a9ae1");
        let iv = packet_iv(&salt, 0xcafe_babe, 0x0001_0002_0003);
        // salt*2^16 in bytes 0..14, SSRC XORed at 4..8, index at 8..14.
        assert_eq!(to_hex(&iv[0..4]), "30cbbc08");
        assert_eq!(
            to_hex(&iv[4..8]),
            to_hex(&[0x86 ^ 0xca, 0x3d ^ 0xfe, 0x8c ^ 0xba, 0x85 ^ 0xbe])
        );
        assert_eq!(
            to_hex(&iv[8..14]),
            to_hex(&[0xd4, 0x9d ^ 0x01, 0xb3, 0x4a ^ 0x02, 0x9a, 0xe1 ^ 0x03])
        );
        assert_eq!(&iv[14..], &[0, 0]);
    }
}
