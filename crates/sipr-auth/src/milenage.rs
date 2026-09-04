//! Milenage (3GPP TS 35.205/35.206): the f1–f5 and f1*/f5* functions used by
//! IMS AKA (`AKAv1-MD5`, RFC 3310).
//!
//! Behavior mirrors SIPp's `milenage.c` (itself the 3GPP reference in
//! spirit): OP is configured and OPc derived as `E_K(OP) XOR OP`; the
//! rotation constants r1..r5 = 64, 0, 32, 64, 96 bits and c1..c5 = 0, 1, 2,
//! 4, 8 are the standard ones. Verified against TS 35.208 Test Sets 1 and 2.

use crate::aes::encrypt_block;

/// The outputs of f2/f3/f4/f5 for one RAND.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaVector {
    /// f2: the response (RES), 8 bytes.
    pub res: [u8; 8],
    /// f3: the cipher key.
    pub ck: [u8; 16],
    /// f4: the integrity key.
    pub ik: [u8; 16],
    /// f5: the anonymity key.
    pub ak: [u8; 6],
}

/// Derive OPc from OP and K: `E_K(OP) XOR OP`.
#[must_use]
pub fn opc(k: &[u8; 16], op: &[u8; 16]) -> [u8; 16] {
    let mut out = encrypt_block(k, op);
    xor_into(&mut out, op);
    out
}

/// f2, f3, f4, f5 (TS 35.206 §4.1).
#[must_use]
pub fn f2345(k: &[u8; 16], opc: &[u8; 16], rand: &[u8; 16]) -> AkaVector {
    let temp = temp(k, opc, rand);
    let out2 = output(k, opc, &temp, 0, 1);
    let out3 = output(k, opc, &temp, 12, 2);
    let out4 = output(k, opc, &temp, 8, 4);
    let mut res = [0u8; 8];
    res.copy_from_slice(&out2[8..16]);
    let mut ak = [0u8; 6];
    ak.copy_from_slice(&out2[0..6]);
    AkaVector {
        res,
        ck: out3,
        ik: out4,
        ak,
    }
}

/// f1: the network authentication code MAC-A (8 bytes).
#[must_use]
pub fn f1(k: &[u8; 16], opc: &[u8; 16], rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
    let out1 = out1(k, opc, rand, sqn, amf);
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&out1[0..8]);
    mac
}

/// f1*: the resynchronisation code MAC-S (8 bytes).
#[must_use]
pub fn f1_star(
    k: &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
) -> [u8; 8] {
    let out1 = out1(k, opc, rand, sqn, amf);
    let mut mac = [0u8; 8];
    mac.copy_from_slice(&out1[8..16]);
    mac
}

/// f5*: the resynchronisation anonymity key AK* (6 bytes).
#[must_use]
pub fn f5_star(k: &[u8; 16], opc: &[u8; 16], rand: &[u8; 16]) -> [u8; 6] {
    let temp = temp(k, opc, rand);
    let out5 = output(k, opc, &temp, 4, 8);
    let mut ak = [0u8; 6];
    ak.copy_from_slice(&out5[0..6]);
    ak
}

/// `TEMP = E_K(RAND XOR OPc)`.
fn temp(k: &[u8; 16], opc: &[u8; 16], rand: &[u8; 16]) -> [u8; 16] {
    let mut input = *rand;
    xor_into(&mut input, opc);
    encrypt_block(k, &input)
}

/// `OUTn = E_K(rot(TEMP XOR OPc, r) XOR c) XOR OPc`, with `rotate` in bytes
/// and `c` XORed into the last byte of the rotated block.
fn output(k: &[u8; 16], opc: &[u8; 16], temp: &[u8; 16], rotate: usize, c: u8) -> [u8; 16] {
    let mut input = [0u8; 16];
    for i in 0..16 {
        input[(i + rotate) % 16] = temp[i] ^ opc[i];
    }
    input[15] ^= c;
    let mut out = encrypt_block(k, &input);
    xor_into(&mut out, opc);
    out
}

/// `OUT1 = E_K(TEMP XOR rot(IN1 XOR OPc, r1)) XOR OPc`, `IN1 = SQN||AMF||SQN||AMF`.
fn out1(k: &[u8; 16], opc: &[u8; 16], rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 16] {
    let temp = temp(k, opc, rand);
    let mut in1 = [0u8; 16];
    in1[0..6].copy_from_slice(sqn);
    in1[6..8].copy_from_slice(amf);
    in1[8..14].copy_from_slice(sqn);
    in1[14..16].copy_from_slice(amf);
    let mut input = [0u8; 16];
    for i in 0..16 {
        input[(i + 8) % 16] = in1[i] ^ opc[i];
    }
    xor_into(&mut input, &temp);
    let mut out = encrypt_block(k, &input);
    xor_into(&mut out, opc);
    out
}

fn xor_into(dst: &mut [u8; 16], src: &[u8; 16]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
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

    /// 3GPP TS 35.208 §4.3 Test Set 1 — the whole set, so an error in any
    /// one function or in the vectors themselves would show.
    #[test]
    fn ts35208_test_set_1() {
        let k = hex::<16>("465b5ce8b199b49faa5f0a2ee238a6bc");
        let rand = hex::<16>("23553cbe9637a89d218ae64dae47bf35");
        let sqn = hex::<6>("ff9bb4d0b607");
        let amf = hex::<2>("b9b9");
        let op = hex::<16>("cdc202d5123e20f62b6d676ac72cb318");
        let opc_v = opc(&k, &op);
        assert_eq!(opc_v, hex::<16>("cd63cb71954a9f4e48a5994e37a02baf"));
        assert_eq!(
            f1(&k, &opc_v, &rand, &sqn, &amf),
            hex::<8>("4a9ffac354dfafb3")
        );
        assert_eq!(
            f1_star(&k, &opc_v, &rand, &sqn, &amf),
            hex::<8>("01cfaf9ec4e871e9")
        );
        let v = f2345(&k, &opc_v, &rand);
        assert_eq!(v.res, hex::<8>("a54211d5e3ba50bf"));
        assert_eq!(v.ck, hex::<16>("b40ba9a3c58b2a05bbf0d987b21bf8cb"));
        assert_eq!(v.ik, hex::<16>("f769bcd751044604127672711c6d3441"));
        assert_eq!(v.ak, hex::<6>("aa689c648370"));
        assert_eq!(f5_star(&k, &opc_v, &rand), hex::<6>("451e8beca43b"));
    }

    /// 3GPP TS 35.208 §4.3 Test Set 2 — a second, independent set.
    #[test]
    fn ts35208_test_set_2() {
        let k = hex::<16>("0396eb317b6d1c36f19c1c84cd6ffd16");
        let rand = hex::<16>("c00d603103dcee52c4478119494202e8");
        let sqn = hex::<6>("fd8eef40df7d");
        let amf = hex::<2>("af17");
        let op = hex::<16>("ff53bade17df5d4e793073ce9d7579fa");
        let opc_v = opc(&k, &op);
        assert_eq!(opc_v, hex::<16>("53c15671c60a4b731c55b4a441c0bde2"));
        assert_eq!(
            f1(&k, &opc_v, &rand, &sqn, &amf),
            hex::<8>("5df5b31807e258b0")
        );
        let v = f2345(&k, &opc_v, &rand);
        assert_eq!(v.res, hex::<8>("d3a628ed988620f0"));
        assert_eq!(v.ck, hex::<16>("58c433ff7a7082acd424220f2b67c556"));
        assert_eq!(v.ik, hex::<16>("21a8c1f929702adb3e738488b9f5c5da"));
        assert_eq!(v.ak, hex::<6>("c47783995f72"));
    }
}
