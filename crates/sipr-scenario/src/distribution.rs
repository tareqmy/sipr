//! Statistical distributions for `<pause distribution="…">` and the
//! `<sample>` action (docs/SIPP_COMPAT.md §1, §6 M38).
//!
//! SIPp names each distribution and its parameters as XML attributes
//! (`distribution="normal" mean="60000" stdev="15000"`), with the attribute
//! names chosen "to be as consistent with Wikipedia's distribution
//! description pages" (SIPp's `ownscenarios.rst`). The parameterisation
//! follows GSL, which SIPp samples with: `mean`/`stdev` of a lognormal are
//! the log-space parameters, a Weibull's `lambda` is its scale and `k` its
//! shape, a Pareto's `k` is its shape and `x_m` its minimum, a gamma's `k` is
//! its shape and `theta` its scale.
//!
//! This module holds the description of a distribution; sampling lives in
//! the engine, next to its seeded generator.

use std::fmt::Write as _;

/// A parsed distribution, one variant per SIPp kind.
#[derive(Debug, Clone, PartialEq)]
pub enum Distribution {
    /// `distribution="fixed" value="…"` — always the same value.
    Fixed {
        /// The value.
        value: f64,
    },
    /// `distribution="uniform" min="…" max="…"`.
    Uniform {
        /// Lower bound.
        min: f64,
        /// Upper bound.
        max: f64,
    },
    /// `distribution="normal" mean="…" stdev="…"`.
    Normal {
        /// Mean.
        mean: f64,
        /// Standard deviation.
        stdev: f64,
    },
    /// `distribution="lognormal" mean="…" stdev="…"` — the parameters of
    /// the underlying normal (GSL's `zeta`, `sigma`).
    LogNormal {
        /// Mean of the logarithm.
        mean: f64,
        /// Standard deviation of the logarithm.
        stdev: f64,
    },
    /// `distribution="exponential" mean="…"`.
    Exponential {
        /// Mean (`1/λ`).
        mean: f64,
    },
    /// `distribution="weibull" lambda="…" k="…"` — scale `lambda`, shape `k`.
    Weibull {
        /// Scale.
        lambda: f64,
        /// Shape.
        k: f64,
    },
    /// `distribution="pareto" k="…" x_m="…"` — shape `k`, minimum `x_m`.
    Pareto {
        /// Shape.
        k: f64,
        /// Minimum (scale).
        x_m: f64,
    },
    /// `distribution="gpareto" shape="…" scale="…" location="…"` — the
    /// generalized Pareto distribution, sampled by inverse CDF as SIPp does.
    GPareto {
        /// Shape (`ξ`).
        shape: f64,
        /// Scale (`σ`).
        scale: f64,
        /// Location (`μ`).
        location: f64,
    },
    /// `distribution="gamma" k="…" theta="…"` — shape `k`, scale `theta`.
    Gamma {
        /// Shape.
        k: f64,
        /// Scale.
        theta: f64,
    },
    /// `distribution="negbin" p="…" n="…"` — the number of failures before
    /// `n` successes with success probability `p` (GSL's meaning; see §6 for
    /// SIPp's argument swap).
    NegBin {
        /// Success probability.
        p: f64,
        /// Number of successes.
        n: f64,
    },
}

/// The distribution names SIPp accepts, in its order.
pub const KINDS: &[&str] = &[
    "fixed",
    "uniform",
    "normal",
    "lognormal",
    "exponential",
    "weibull",
    "pareto",
    "gpareto",
    "gamma",
    "negbin",
];

/// Old-style `<pause>` attributes whose presence names a distribution
/// (`parse_distribution(oldstyle=true)` in SIPp's `scenario.cpp`).
const OLD_STYLE_FLAGS: &[&str] = &[
    "normal",
    "exponential",
    "lognormal",
    "weibull",
    "pareto",
    "gamma",
];

/// SIPp's human name for a kind, used in its error messages
/// (`xp_get_double(name, what)`).
fn what(kind: &str) -> &'static str {
    match kind {
        "fixed" => "Fixed distribution",
        "uniform" => "Uniform distribution",
        "normal" => "Normal distribution",
        "lognormal" => "Lognormal distribution",
        "exponential" => "Exponential distribution",
        "weibull" => "Weibull distribution",
        "pareto" => "Pareto distribution",
        "gpareto" => "Generalized Pareto distribution",
        "gamma" => "Gamma distribution",
        "negbin" => "Negative Binomial distribution",
        _ => "distribution",
    }
}

/// The parameter attributes of `kind`, in SIPp's order.
pub fn params_of(kind: &str) -> &'static [&'static str] {
    match kind {
        "fixed" => &["value"],
        "uniform" => &["min", "max"],
        "normal" | "lognormal" => &["mean", "stdev"],
        "exponential" => &["mean"],
        "weibull" => &["lambda", "k"],
        "pareto" => &["k", "x_m"],
        "gpareto" => &["shape", "scale", "location"],
        "gamma" => &["k", "theta"],
        "negbin" => &["p", "n"],
        _ => &[],
    }
}

/// Every attribute name any distribution reads, for unknown-attribute
/// warnings on `<pause>` (`old_style`, which also accepts the legacy flag
/// spellings) and `<sample>`.
#[must_use]
pub fn all_param_attrs(old_style: bool) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = vec!["distribution"];
    for kind in KINDS {
        for p in params_of(kind) {
            if !out.contains(p) {
                out.push(p);
            }
        }
    }
    if old_style {
        out.extend(OLD_STYLE_FLAGS);
    }
    out
}

/// Which distribution an element names, or `None` when it names none
/// (an old-style `<pause>` with `milliseconds` or no attributes).
///
/// `old_style` enables SIPp's legacy `<pause>` spellings: `min`/`max`
/// alone mean `uniform`, and a bare `normal="…"`/`exponential="…"`/… flag
/// names that kind, its parameters read from the usual attributes.
pub fn kind_of<'a>(attr: &dyn Fn(&str) -> Option<&'a str>, old_style: bool) -> Option<String> {
    if let Some(name) = attr("distribution") {
        return Some(name.to_owned());
    }
    if !old_style {
        return None;
    }
    for flag in OLD_STYLE_FLAGS {
        if attr(flag).is_some() {
            return Some((*flag).to_owned());
        }
    }
    if attr("min").is_some() || attr("max").is_some() {
        return Some("uniform".to_owned());
    }
    None
}

/// Build the distribution `kind` from the element's attributes, with SIPp's
/// error wording for a missing or malformed parameter.
///
/// `kind` may also carry sipr's positional shorthand, `kind(a,b,…)`, whose
/// values stand in for the attributes in SIPp's order.
pub fn from_attrs<'a>(
    kind: &str,
    attr: &dyn Fn(&str) -> Option<&'a str>,
) -> Result<Distribution, String> {
    let (name, positional) = split_shorthand(kind)?;
    let name = name.trim();
    if !KINDS.contains(&name) {
        return Err(format!("Unknown distribution: {name}"));
    }
    let what = what(name);
    let mut values = Vec::with_capacity(3);
    for (i, param) in params_of(name).iter().enumerate() {
        let raw = match positional.get(i) {
            Some(v) => Some(v.as_str()),
            None => attr(param),
        };
        let Some(raw) = raw else {
            return Err(format!(
                "{what} is missing the required '{param}' parameter."
            ));
        };
        let value: f64 = raw
            .trim()
            .parse()
            .map_err(|_| format!("{what} '{param}' parameter: bad numeric value '{raw}'"))?;
        values.push(value);
    }
    Ok(build(name, &values))
}

/// `"uniform(200,3000)"` → `("uniform", ["200", "3000"])`; a bare name has
/// no positional values.
fn split_shorthand(kind: &str) -> Result<(&str, Vec<String>), String> {
    let Some((name, rest)) = kind.split_once('(') else {
        return Ok((kind, Vec::new()));
    };
    let Some(inner) = rest.strip_suffix(')') else {
        return Err(format!("Unknown distribution: {kind}"));
    };
    let values = inner
        .split(',')
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .collect();
    Ok((name, values))
}

fn build(name: &str, v: &[f64]) -> Distribution {
    // `from_attrs` collected exactly `params_of(name).len()` values.
    let at = |i: usize| v.get(i).copied().unwrap_or(0.0);
    match name {
        "fixed" => Distribution::Fixed { value: at(0) },
        "uniform" => Distribution::Uniform {
            min: at(0),
            max: at(1),
        },
        "normal" => Distribution::Normal {
            mean: at(0),
            stdev: at(1),
        },
        "lognormal" => Distribution::LogNormal {
            mean: at(0),
            stdev: at(1),
        },
        "exponential" => Distribution::Exponential { mean: at(0) },
        "weibull" => Distribution::Weibull {
            lambda: at(0),
            k: at(1),
        },
        "pareto" => Distribution::Pareto {
            k: at(0),
            x_m: at(1),
        },
        "gpareto" => Distribution::GPareto {
            shape: at(0),
            scale: at(1),
            location: at(2),
        },
        "gamma" => Distribution::Gamma {
            k: at(0),
            theta: at(1),
        },
        _ => Distribution::NegBin { p: at(0), n: at(1) },
    }
}

/// The standard normal's 99th percentile, `Φ⁻¹(0.99)`.
const Z_99: f64 = 2.326_347_874_040_841;

impl Distribution {
    /// SIPp's name for the kind (`distribution="…"`).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Fixed { .. } => "fixed",
            Self::Uniform { .. } => "uniform",
            Self::Normal { .. } => "normal",
            Self::LogNormal { .. } => "lognormal",
            Self::Exponential { .. } => "exponential",
            Self::Weibull { .. } => "weibull",
            Self::Pareto { .. } => "pareto",
            Self::GPareto { .. } => "gpareto",
            Self::Gamma { .. } => "gamma",
            Self::NegBin { .. } => "negbin",
        }
    }

    /// SIPp's short description of the distribution (`CSample::textDescr`):
    /// `N(mean,stdev)`, `LN(…)`, `Exp(mean)`, `Wb(lambda,k)`, `P(k,x_m)`,
    /// `P(shape,scale,location)`, `G(k,theta)`, `NB(p,n)`, `min/max`, or the
    /// fixed value.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut s = String::new();
        match self {
            Self::Fixed { value } => {
                let _ = write!(s, "{value:.6}");
            }
            Self::Uniform { min, max } => {
                let _ = write!(s, "{min:.6}/{max:.6}");
            }
            Self::Normal { mean, stdev } => {
                let _ = write!(s, "N({mean:.3},{stdev:.3})");
            }
            Self::LogNormal { mean, stdev } => {
                let _ = write!(s, "LN({mean:.3},{stdev:.3})");
            }
            Self::Exponential { mean } => {
                let _ = write!(s, "Exp({mean:.6})");
            }
            Self::Weibull { lambda, k } => {
                let _ = write!(s, "Wb({lambda:.3},{k:.3})");
            }
            Self::Pareto { k, x_m } => {
                let _ = write!(s, "P({k:.3},{x_m:.3})");
            }
            Self::GPareto {
                shape,
                scale,
                location,
            } => {
                let _ = write!(s, "P({shape:.3},{scale:.3},{location:.3})");
            }
            Self::Gamma { k, theta } => {
                let _ = write!(s, "G({k:.3},{theta:.3})");
            }
            Self::NegBin { p, n } => {
                let _ = write!(s, "NB({p:.3},{n:.3})");
            }
        }
        s
    }

    /// The 99th percentile (`CSample::cdfInv(0.99)`), used by the
    /// `sanity_check` on `<pause>`. `None` where SIPp does not implement it
    /// (negative binomial). The gamma value is the Wilson–Hilferty
    /// approximation, close enough for a sanity check against `INT_MAX`.
    #[must_use]
    pub fn percentile_99(&self) -> Option<f64> {
        const P: f64 = 0.99;
        Some(match self {
            Self::Fixed { value } => *value,
            Self::Uniform { min, max } => (max - min).mul_add(P, *min),
            Self::Normal { mean, stdev } => stdev.mul_add(Z_99, *mean),
            Self::LogNormal { mean, stdev } => stdev.mul_add(Z_99, *mean).exp(),
            Self::Exponential { mean } => -mean * (1.0 - P).ln(),
            Self::Weibull { lambda, k } => lambda * (-(1.0 - P).ln()).powf(1.0 / k),
            Self::Pareto { k, x_m } => x_m * (1.0 - P).powf(-1.0 / k),
            Self::GPareto {
                shape,
                scale,
                location,
            } => gpareto_quantile(*shape, *scale, *location, P),
            Self::Gamma { k, theta } => {
                let c = 1.0 / (9.0 * k);
                k * theta * Z_99.mul_add(c.sqrt(), 1.0 - c).powi(3)
            }
            Self::NegBin { .. } => return None,
        })
    }
}

/// SIPp's generalized Pareto inverse CDF, `location + scale·(u^-shape − 1)/shape`,
/// with the `shape → 0` limit `location − scale·ln(u)` instead of a division
/// by zero.
#[must_use]
pub fn gpareto_quantile(shape: f64, scale: f64, location: f64, u: f64) -> f64 {
    if shape == 0.0 {
        return scale.mul_add(-u.ln(), location);
    }
    location + scale * (u.powf(-shape) - 1.0) / shape
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn parse(kind: &str, pairs: &[(&str, &str)]) -> Result<Distribution, String> {
        let map = attrs(pairs);
        from_attrs(kind, &|name| map.get(name).map(String::as_str))
    }

    #[test]
    fn every_kind_parses_from_sipp_attributes() {
        assert_eq!(
            parse("fixed", &[("value", "1000")]),
            Ok(Distribution::Fixed { value: 1000.0 })
        );
        assert_eq!(
            parse("uniform", &[("min", "2000"), ("max", "5000")]),
            Ok(Distribution::Uniform {
                min: 2000.0,
                max: 5000.0
            })
        );
        assert_eq!(
            parse("normal", &[("mean", "60000"), ("stdev", "15000")]),
            Ok(Distribution::Normal {
                mean: 60000.0,
                stdev: 15000.0
            })
        );
        assert_eq!(
            parse("lognormal", &[("mean", "12.28"), ("stdev", "1")]),
            Ok(Distribution::LogNormal {
                mean: 12.28,
                stdev: 1.0
            })
        );
        assert_eq!(
            parse("exponential", &[("mean", "900000")]),
            Ok(Distribution::Exponential { mean: 900000.0 })
        );
        assert_eq!(
            parse("weibull", &[("lambda", "3"), ("k", "4")]),
            Ok(Distribution::Weibull {
                lambda: 3.0,
                k: 4.0
            })
        );
        assert_eq!(
            parse("pareto", &[("k", "1"), ("x_m", "2")]),
            Ok(Distribution::Pareto { k: 1.0, x_m: 2.0 })
        );
        assert_eq!(
            parse(
                "gpareto",
                &[("shape", "0.5"), ("scale", "100"), ("location", "10")]
            ),
            Ok(Distribution::GPareto {
                shape: 0.5,
                scale: 100.0,
                location: 10.0
            })
        );
        assert_eq!(
            parse("gamma", &[("k", "3"), ("theta", "2")]),
            Ok(Distribution::Gamma { k: 3.0, theta: 2.0 })
        );
        assert_eq!(
            parse("negbin", &[("p", "0.1"), ("n", "2")]),
            Ok(Distribution::NegBin { p: 0.1, n: 2.0 })
        );
    }

    #[test]
    fn shorthand_takes_positional_values_in_sipp_order() {
        assert_eq!(
            parse("uniform(200,3000)", &[]),
            Ok(Distribution::Uniform {
                min: 200.0,
                max: 3000.0
            })
        );
        assert_eq!(
            parse("gpareto(0.5, 100, 10)", &[]),
            Ok(Distribution::GPareto {
                shape: 0.5,
                scale: 100.0,
                location: 10.0
            })
        );
        // A partial shorthand falls back to the attributes for the rest.
        assert_eq!(
            parse("normal(50)", &[("stdev", "5")]),
            Ok(Distribution::Normal {
                mean: 50.0,
                stdev: 5.0
            })
        );
    }

    #[test]
    fn errors_use_sipp_wording() {
        assert_eq!(
            parse("normal", &[("mean", "1")]),
            Err("Normal distribution is missing the required 'stdev' parameter.".to_owned())
        );
        assert_eq!(
            parse("poisson", &[]),
            Err("Unknown distribution: poisson".to_owned())
        );
        assert_eq!(
            parse("uniform(1", &[]),
            Err("Unknown distribution: uniform(1".to_owned())
        );
        assert!(
            parse("exponential", &[("mean", "fast")])
                .unwrap_err()
                .contains("Exponential distribution 'mean' parameter")
        );
    }

    #[test]
    fn old_style_pause_attributes_name_a_kind() {
        let uniform = attrs(&[("min", "1"), ("max", "2")]);
        assert_eq!(
            kind_of(&|n| uniform.get(n).map(String::as_str), true).as_deref(),
            Some("uniform")
        );
        let normal = attrs(&[("normal", "1"), ("mean", "1"), ("stdev", "2")]);
        assert_eq!(
            kind_of(&|n| normal.get(n).map(String::as_str), true).as_deref(),
            Some("normal")
        );
        // <sample> has no old style.
        assert_eq!(
            kind_of(&|n| uniform.get(n).map(String::as_str), false),
            None
        );
        let explicit = attrs(&[("distribution", "gamma"), ("min", "1")]);
        assert_eq!(
            kind_of(&|n| explicit.get(n).map(String::as_str), true).as_deref(),
            Some("gamma")
        );
    }

    #[test]
    fn descriptions_follow_sipp_textdescr() {
        let cases: &[(Distribution, &str)] = &[
            (Distribution::Fixed { value: 1000.0 }, "1000.000000"),
            (
                Distribution::Uniform {
                    min: 200.0,
                    max: 3000.0,
                },
                "200.000000/3000.000000",
            ),
            (
                Distribution::Normal {
                    mean: 60000.0,
                    stdev: 15000.0,
                },
                "N(60000.000,15000.000)",
            ),
            (
                Distribution::LogNormal {
                    mean: 12.28,
                    stdev: 1.0,
                },
                "LN(12.280,1.000)",
            ),
            (Distribution::Exponential { mean: 900.0 }, "Exp(900.000000)"),
            (
                Distribution::Weibull {
                    lambda: 3.0,
                    k: 4.0,
                },
                "Wb(3.000,4.000)",
            ),
            (Distribution::Pareto { k: 1.0, x_m: 2.0 }, "P(1.000,2.000)"),
            (
                Distribution::GPareto {
                    shape: 0.5,
                    scale: 100.0,
                    location: 10.0,
                },
                "P(0.500,100.000,10.000)",
            ),
            (Distribution::Gamma { k: 3.0, theta: 2.0 }, "G(3.000,2.000)"),
            (Distribution::NegBin { p: 0.1, n: 2.0 }, "NB(0.100,2.000)"),
        ];
        for (d, want) in cases {
            assert_eq!(d.describe(), *want);
        }
    }

    #[test]
    fn percentile_99_matches_closed_forms() {
        let close = |a: f64, b: f64| (a - b).abs() < 1e-6 * b.abs().max(1.0);
        assert!(close(
            Distribution::Fixed { value: 7.0 }.percentile_99().unwrap(),
            7.0
        ));
        assert!(close(
            Distribution::Uniform {
                min: 100.0,
                max: 200.0
            }
            .percentile_99()
            .unwrap(),
            199.0
        ));
        assert!(close(
            Distribution::Normal {
                mean: 0.0,
                stdev: 1.0
            }
            .percentile_99()
            .unwrap(),
            Z_99
        ));
        assert!(close(
            Distribution::Exponential { mean: 1.0 }
                .percentile_99()
                .unwrap(),
            (100.0f64).ln()
        ));
        assert!(close(
            Distribution::Weibull {
                lambda: 2.0,
                k: 1.0
            }
            .percentile_99()
            .unwrap(),
            2.0 * (100.0f64).ln()
        ));
        assert!(close(
            Distribution::Pareto { k: 1.0, x_m: 2.0 }
                .percentile_99()
                .unwrap(),
            200.0
        ));
        assert!(close(
            Distribution::GPareto {
                shape: 0.0,
                scale: 1.0,
                location: 5.0
            }
            .percentile_99()
            .unwrap(),
            5.0 - (0.99f64).ln()
        ));
        // Gamma(k=1, θ=1) is Exp(1): Wilson–Hilferty is within 1 % there.
        let g = Distribution::Gamma { k: 1.0, theta: 1.0 }
            .percentile_99()
            .unwrap();
        assert!((g - (100.0f64).ln()).abs() < 0.05, "{g}");
        assert_eq!(
            Distribution::NegBin { p: 0.5, n: 1.0 }.percentile_99(),
            None
        );
    }
}
