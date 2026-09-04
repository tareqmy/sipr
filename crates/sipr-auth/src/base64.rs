//! Base64 (RFC 4648) decode/encode, enough for AKA nonces: the challenge
//! nonce is base64(RAND || AUTN [|| server data]).
//!
//! Tolerant on input, as befits something a real server produced: padding
//! may be absent, and whitespace is ignored. Any other non-alphabet byte
//! is a hard error (SIPp rejects malformed base64 too).

/// Decode `text`, returning `None` for a non-base64 character or an
/// impossible length.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut sextets = 0usize;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        sextets += 1;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // A single trailing sextet cannot encode a byte.
    if sextets % 4 == 1 {
        return None;
    }
    Some(out)
}

/// Encode `data` with standard padding.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_round_trip() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn tolerant_of_missing_padding_and_whitespace() {
        assert_eq!(decode("Zg").unwrap(), b"f");
        assert_eq!(decode("Zm9v\r\nYmFy").unwrap(), b"foobar");
        assert_eq!(decode("Zm9vYmE").unwrap(), b"fooba");
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode("Zm9v!").is_none());
        assert!(decode("Z").is_none());
        assert!(decode("Zm9vY").is_none());
    }

    #[test]
    fn binary_round_trip() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }
}
