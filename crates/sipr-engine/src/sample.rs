//! Drawing from the statistical distributions of `<pause distribution=…>`
//! and `<sample>` (docs/SIPP_COMPAT.md §6 M38).
//!
//! One draw per pause step or per `<sample>` action, never on the
//! per-message hot path, from the engine's seeded generator so a run is
//! reproducible. The parameterisation is GSL's, which SIPp samples with;
//! the methods are the textbook ones: inverse CDF where it is closed-form,
//! Box–Muller for the normal, Marsaglia–Tsang for the gamma, and the
//! gamma–Poisson mixture for the negative binomial.

use sipr_net::rng::Rng;
use sipr_scenario::distribution::{Distribution, gpareto_quantile};

/// One draw from `d`.
pub fn sample(d: &Distribution, rng: &mut Rng) -> f64 {
    match *d {
        Distribution::Fixed { value } => value,
        Distribution::Uniform { min, max } => rng.next_f64().mul_add(max - min, min),
        Distribution::Normal { mean, stdev } => standard_normal(rng).mul_add(stdev, mean),
        Distribution::LogNormal { mean, stdev } => standard_normal(rng).mul_add(stdev, mean).exp(),
        Distribution::Exponential { mean } => exponential(rng) * mean,
        Distribution::Weibull { lambda, k } => lambda * exponential(rng).powf(1.0 / k),
        Distribution::Pareto { k, x_m } => x_m * open_unit(rng).powf(-1.0 / k),
        Distribution::GPareto {
            shape,
            scale,
            location,
        } => gpareto_quantile(shape, scale, location, open_unit(rng)),
        Distribution::Gamma { k, theta } => gamma(k, rng) * theta,
        Distribution::NegBin { p, n } => negative_binomial(p, n, rng),
    }
}

/// A sampled pause in whole milliseconds. SIPp treats anything below 1 —
/// including the negative tail of a normal — as no pause at all rather than
/// letting the cast wrap to ~50 hours (`call.cpp`, the pause branch of
/// `call::run`).
#[must_use]
pub fn pause_millis(sample: f64) -> u64 {
    if sample.is_nan() || sample < 1.0 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ms = sample as u64;
    ms
}

/// Uniform on the open interval (0, 1): a zero would make the logarithms
/// below infinite.
fn open_unit(rng: &mut Rng) -> f64 {
    let u = rng.next_f64();
    if u == 0.0 { f64::MIN_POSITIVE } else { u }
}

/// Exp(1) by inversion.
fn exponential(rng: &mut Rng) -> f64 {
    -open_unit(rng).ln()
}

/// N(0, 1) by Box–Muller (one of the pair; the other is discarded).
fn standard_normal(rng: &mut Rng) -> f64 {
    let u1 = open_unit(rng);
    let u2 = rng.next_f64();
    (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
}

/// Gamma(k, 1) by Marsaglia–Tsang; shapes below 1 use their boost,
/// `Gamma(k+1) · U^(1/k)`. A non-positive shape yields 0.
fn gamma(k: f64, rng: &mut Rng) -> f64 {
    if k.is_nan() || k <= 0.0 {
        return 0.0;
    }
    if k < 1.0 {
        return gamma(k + 1.0, rng) * open_unit(rng).powf(1.0 / k);
    }
    let d = k - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();
    loop {
        let x = standard_normal(rng);
        let v = c.mul_add(x, 1.0).powi(3);
        if v <= 0.0 {
            continue;
        }
        let u = open_unit(rng);
        if u.ln() < (0.5 * x * x) + d - d * v + d * v.ln() {
            return d * v;
        }
    }
}

/// Poisson(mu): counting Exp(1) arrivals up to `mu` for small means, and
/// the normal approximation with continuity correction past 30, where the
/// count would cost thousands of draws per sample.
fn poisson(mu: f64, rng: &mut Rng) -> f64 {
    if mu.is_nan() || mu <= 0.0 {
        return 0.0;
    }
    if mu < 30.0 {
        let mut count = 0.0;
        let mut t = exponential(rng);
        while t <= mu {
            count += 1.0;
            t += exponential(rng);
        }
        return count;
    }
    (standard_normal(rng).mul_add(mu.sqrt(), mu) + 0.5)
        .floor()
        .max(0.0)
}

/// Failures before `n` successes at success probability `p`, as GSL draws
/// it: a Poisson whose mean is Gamma(n, 1) scaled by `(1-p)/p`. A `p`
/// outside (0, 1] has no meaning and yields 0.
fn negative_binomial(p: f64, n: f64, rng: &mut Rng) -> f64 {
    if p.is_nan() || p <= 0.0 || p > 1.0 {
        return 0.0;
    }
    let x = gamma(n, rng);
    poisson(x * (1.0 - p) / p, rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DRAWS: usize = 200_000;

    fn draws(d: &Distribution) -> Vec<f64> {
        let mut rng = Rng::new(0xD15C_0DE5);
        (0..DRAWS).map(|_| sample(d, &mut rng)).collect()
    }

    fn mean(v: &[f64]) -> f64 {
        v.iter().sum::<f64>() / v.len() as f64
    }

    fn variance(v: &[f64]) -> f64 {
        let m = mean(v);
        v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64
    }

    fn median(v: &[f64]) -> f64 {
        let mut s = v.to_vec();
        s.sort_by(f64::total_cmp);
        s[s.len() / 2]
    }

    #[track_caller]
    fn assert_close(got: f64, want: f64, tolerance: f64) {
        assert!(
            (got - want).abs() <= tolerance * want.abs().max(1.0),
            "got {got}, want {want} ± {}%",
            tolerance * 100.0
        );
    }

    #[test]
    fn fixed_and_uniform() {
        assert!(
            draws(&Distribution::Fixed { value: 42.0 })
                .iter()
                .all(|x| *x == 42.0)
        );
        let u = draws(&Distribution::Uniform {
            min: 200.0,
            max: 3000.0,
        });
        assert!(u.iter().all(|x| (200.0..3000.0).contains(x)));
        assert_close(mean(&u), 1600.0, 0.01);
    }

    #[test]
    fn normal_and_lognormal() {
        let n = draws(&Distribution::Normal {
            mean: 1000.0,
            stdev: 100.0,
        });
        assert_close(mean(&n), 1000.0, 0.002);
        assert_close(variance(&n).sqrt(), 100.0, 0.02);
        // E = exp(μ + σ²/2)
        let ln = draws(&Distribution::LogNormal {
            mean: 5.0,
            stdev: 0.5,
        });
        assert_close(mean(&ln), (5.0f64 + 0.125).exp(), 0.02);
        assert!(ln.iter().all(|x| *x > 0.0));
    }

    #[test]
    fn exponential_and_weibull() {
        let e = draws(&Distribution::Exponential { mean: 250.0 });
        assert_close(mean(&e), 250.0, 0.02);
        assert_close(variance(&e), 250.0 * 250.0, 0.05);
        // Weibull mean = λ·Γ(1 + 1/k); Γ(1.25) = 0.906402…
        let w = draws(&Distribution::Weibull {
            lambda: 3.0,
            k: 4.0,
        });
        assert_close(mean(&w), 3.0 * 0.906_402_477, 0.01);
    }

    #[test]
    fn pareto_and_generalized_pareto() {
        // Pareto mean = k·x_m / (k − 1) for k > 1; every draw ≥ x_m.
        let p = draws(&Distribution::Pareto { k: 3.0, x_m: 2.0 });
        assert!(p.iter().all(|x| *x >= 2.0));
        assert_close(mean(&p), 3.0, 0.03);
        // SIPp's quantile with u uniform: median at u = ½.
        let gp = draws(&Distribution::GPareto {
            shape: 0.5,
            scale: 100.0,
            location: 10.0,
        });
        assert_close(median(&gp), gpareto_quantile(0.5, 100.0, 10.0, 0.5), 0.02);
        // shape → 0 is location + Exp(scale).
        let gp0 = draws(&Distribution::GPareto {
            shape: 0.0,
            scale: 100.0,
            location: 10.0,
        });
        assert_close(mean(&gp0), 110.0, 0.02);
    }

    #[test]
    fn gamma_shapes_above_and_below_one() {
        let g = draws(&Distribution::Gamma { k: 3.0, theta: 2.0 });
        assert_close(mean(&g), 6.0, 0.02);
        assert_close(variance(&g), 12.0, 0.05);
        let small = draws(&Distribution::Gamma { k: 0.5, theta: 2.0 });
        assert_close(mean(&small), 1.0, 0.03);
        assert_close(variance(&small), 2.0, 0.05);
        assert!(
            draws(&Distribution::Gamma { k: 0.0, theta: 2.0 })
                .iter()
                .all(|x| *x == 0.0)
        );
    }

    #[test]
    fn negative_binomial_and_poisson() {
        // mean n(1−p)/p, variance n(1−p)/p², integer-valued.
        let nb = draws(&Distribution::NegBin { p: 0.5, n: 2.0 });
        assert!(nb.iter().all(|x| x.fract() == 0.0 && *x >= 0.0));
        assert_close(mean(&nb), 2.0, 0.03);
        assert_close(variance(&nb), 4.0, 0.05);
        let mut rng = Rng::new(7);
        let big: Vec<f64> = (0..DRAWS).map(|_| poisson(100.0, &mut rng)).collect();
        assert_close(mean(&big), 100.0, 0.01);
        assert_close(variance(&big), 100.0, 0.05);
        let small: Vec<f64> = (0..DRAWS).map(|_| poisson(4.0, &mut rng)).collect();
        assert_close(mean(&small), 4.0, 0.02);
        assert_close(variance(&small), 4.0, 0.05);
        // A probability outside (0, 1] is meaningless: 0, not garbage.
        assert!(
            draws(&Distribution::NegBin { p: 2.0, n: 2.0 })
                .iter()
                .all(|x| *x == 0.0)
        );
    }

    #[test]
    fn pause_millis_follows_sipp_clamp() {
        assert_eq!(pause_millis(-5.0), 0);
        assert_eq!(pause_millis(0.999), 0);
        assert_eq!(pause_millis(1.0), 1);
        assert_eq!(pause_millis(1999.9), 1999);
        assert_eq!(pause_millis(f64::NAN), 0);
    }

    #[test]
    fn same_seed_same_draws() {
        let d = Distribution::Normal {
            mean: 0.0,
            stdev: 1.0,
        };
        let a: Vec<f64> = {
            let mut r = Rng::new(3);
            (0..10).map(|_| sample(&d, &mut r)).collect()
        };
        let b: Vec<f64> = {
            let mut r = Rng::new(3);
            (0..10).map(|_| sample(&d, &mut r)).collect()
        };
        assert_eq!(a, b);
    }
}
