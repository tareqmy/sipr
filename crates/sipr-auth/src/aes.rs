//! AES-128 single-block encryption (FIPS 197), the kernel of Milenage.
//!
//! In-tree for the same reason as the hashes in `hash.rs`: one short,
//! standard algorithm, verified against its canonical test vector. Only
//! encryption of one block with a 128-bit key is needed — Milenage never
//! decrypts and never uses a mode of operation.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const ROUNDS: usize = 10;

/// Multiply by x in GF(2^8) (xtime).
fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

/// Expand a 128-bit key into 11 round keys.
fn expand_key(key: &[u8; 16]) -> [[u8; 16]; ROUNDS + 1] {
    let mut w = [[0u8; 4]; 4 * (ROUNDS + 1)];
    for (i, word) in w.iter_mut().take(4).enumerate() {
        word.copy_from_slice(&key[4 * i..4 * i + 4]);
    }
    let mut rcon = 1u8;
    for i in 4..w.len() {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t = [
                SBOX[t[1] as usize] ^ rcon,
                SBOX[t[2] as usize],
                SBOX[t[3] as usize],
                SBOX[t[0] as usize],
            ];
            rcon = xtime(rcon);
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ t[j];
        }
    }
    let mut round_keys = [[0u8; 16]; ROUNDS + 1];
    for (r, rk) in round_keys.iter_mut().enumerate() {
        for c in 0..4 {
            rk[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
        }
    }
    round_keys
}

fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(rk) {
        *s ^= k;
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for s in state.iter_mut() {
        *s = SBOX[*s as usize];
    }
}

/// State is column-major: byte `4*c + r` is row `r`, column `c`.
fn shift_rows(state: &mut [u8; 16]) {
    let s = *state;
    for c in 0..4 {
        for r in 0..4 {
            state[4 * c + r] = s[4 * ((c + r) % 4) + r];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [
            state[4 * c],
            state[4 * c + 1],
            state[4 * c + 2],
            state[4 * c + 3],
        ];
        let all = col[0] ^ col[1] ^ col[2] ^ col[3];
        for r in 0..4 {
            let a = col[r];
            let b = col[(r + 1) % 4];
            state[4 * c + r] = a ^ all ^ xtime(a ^ b);
        }
    }
}

/// Encrypt one 16-byte block under `key`.
#[must_use]
pub fn encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let round_keys = expand_key(key);
    let mut state = *block;
    add_round_key(&mut state, &round_keys[0]);
    for rk in round_keys.iter().take(ROUNDS).skip(1) {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, rk);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[ROUNDS]);
    state
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// FIPS 197 Appendix C.1 (AES-128).
    #[test]
    fn fips197_appendix_c1() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let pt = hex("00112233445566778899aabbccddeeff");
        assert_eq!(
            encrypt_block(&key, &pt),
            hex("69c4e0d86a7b0430d8cdb78070b4c55a")
        );
    }

    /// FIPS 197 Appendix B (the worked example).
    #[test]
    fn fips197_appendix_b() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hex("3243f6a8885a308d313198a2e0370734");
        assert_eq!(
            encrypt_block(&key, &pt),
            hex("3925841d02dc09fbdc118597196a0b32")
        );
    }
}
