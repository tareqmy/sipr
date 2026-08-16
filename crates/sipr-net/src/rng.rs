//! A tiny deterministic PRNG (xorshift64*) for loss simulation and tests.
//!
//! Not cryptographic and not meant to be: `lost="10"` needs a fast, seedable
//! coin flip, and the fuzz-style tests need reproducible byte streams.

/// xorshift64* generator.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// Seeded generator; a zero seed is nudged to a fixed constant.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// Next raw 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform float in [0, 1).
    pub fn next_f64(&mut self) -> f64 {
        // 53 high-quality bits → [0,1).
        #[allow(clippy::cast_precision_loss)]
        let v = (self.next_u64() >> 11) as f64;
        v / (1u64 << 53) as f64
    }

    /// Bernoulli trial: true with probability `pct` percent (0..=100).
    pub fn chance_pct(&mut self, pct: f64) -> bool {
        if pct <= 0.0 {
            return false;
        }
        if pct >= 100.0 {
            return true;
        }
        self.next_f64() * 100.0 < pct
    }

    /// Fill `buf` with pseudo-random bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn chance_extremes() {
        let mut r = Rng::new(7);
        assert!(!r.chance_pct(0.0));
        assert!(r.chance_pct(100.0));
    }

    #[test]
    fn chance_is_roughly_calibrated() {
        let mut r = Rng::new(1234);
        let hits = (0..10_000).filter(|_| r.chance_pct(10.0)).count();
        assert!((800..1200).contains(&hits), "10% of 10k ≈ 1000, got {hits}");
    }

    #[test]
    fn fill_covers_partial_chunks() {
        let mut r = Rng::new(9);
        let mut buf = [0u8; 13];
        r.fill(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
