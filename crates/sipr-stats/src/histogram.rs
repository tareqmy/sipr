//! A small fixed-memory latency histogram: 1 ms buckets up to 10 s plus an
//! overflow bucket. Exact to the millisecond in the range load tests care
//! about, deterministic, and dependency-free (hdrhistogram is unavailable in
//! this build environment — noted in docs/MILESTONES.md M4).

/// Bucketed millisecond histogram with running moments.
#[derive(Debug, Clone)]
pub struct Histogram {
    buckets: Vec<u64>,
    overflow: u64,
    count: u64,
    sum_ms: f64,
    sum_sq_ms: f64,
    min_ms: u64,
    max_ms: u64,
}

const BUCKETS: usize = 10_000; // 0..=9999 ms at 1 ms resolution

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    /// Empty histogram.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: vec![0; BUCKETS],
            overflow: 0,
            count: 0,
            sum_ms: 0.0,
            sum_sq_ms: 0.0,
            min_ms: u64::MAX,
            max_ms: 0,
        }
    }

    /// Record one duration.
    pub fn record(&mut self, d: std::time::Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        match usize::try_from(ms) {
            Ok(i) if i < BUCKETS => self.buckets[i] += 1,
            _ => self.overflow += 1,
        }
        self.count += 1;
        #[allow(clippy::cast_precision_loss)]
        let msf = ms as f64;
        self.sum_ms += msf;
        self.sum_sq_ms += msf * msf;
        self.min_ms = self.min_ms.min(ms);
        self.max_ms = self.max_ms.max(ms);
    }

    /// Number of recorded samples.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Mean in milliseconds (0 when empty).
    #[must_use]
    pub fn mean_ms(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let n = self.count as f64;
        self.sum_ms / n
    }

    /// Population standard deviation in milliseconds.
    #[must_use]
    pub fn stddev_ms(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let n = self.count as f64;
        let mean = self.sum_ms / n;
        (self.sum_sq_ms / n - mean * mean).max(0.0).sqrt()
    }

    /// Minimum in ms (0 when empty).
    #[must_use]
    pub fn min_ms(&self) -> u64 {
        if self.count == 0 { 0 } else { self.min_ms }
    }

    /// Maximum in ms.
    #[must_use]
    pub fn max_ms(&self) -> u64 {
        self.max_ms
    }

    /// Percentile (0.0..=100.0) in ms; overflow reports as 10 000.
    #[must_use]
    pub fn percentile_ms(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let clamped = p.clamp(0.0, 100.0) / 100.0;
        #[allow(clippy::cast_precision_loss)]
        let target_f = (self.count as f64 * clamped).ceil();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let target = (target_f as u64).max(1);
        let mut seen = 0u64;
        for (i, &c) in self.buckets.iter().enumerate() {
            seen += c;
            if seen >= target {
                return i as u64;
            }
        }
        BUCKETS as u64
    }
}

/// A SIPp repartition table: counts of samples per configured bound.
///
/// For bounds `[b1, b2, ..., bn]` the classes are `<b1`, `b1..b2`, ...,
/// `>=bn` — matching SIPp's screen layout.
#[derive(Debug, Clone)]
pub struct Repartition {
    bounds: Vec<u64>,
    counts: Vec<u64>,
}

impl Repartition {
    /// Table with the scenario-configured bounds (ms). Empty bounds → inert.
    #[must_use]
    pub fn new(bounds: &[u64]) -> Self {
        Self {
            bounds: bounds.to_vec(),
            counts: vec![0; bounds.len() + 1],
        }
    }

    /// Record a duration.
    pub fn record(&mut self, d: std::time::Duration) {
        if self.bounds.is_empty() {
            return;
        }
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        let idx = self.bounds.iter().position(|&b| ms < b);
        match idx {
            Some(i) => self.counts[i] += 1,
            None => {
                if let Some(last) = self.counts.last_mut() {
                    *last += 1;
                }
            }
        }
    }

    /// The configured bounds (ms).
    #[must_use]
    pub fn bounds(&self) -> Vec<u64> {
        self.bounds.clone()
    }

    /// Zero every bucket, keeping the bounds (`-periodic_rtd`).
    pub fn reset(&mut self) {
        self.counts.fill(0);
    }

    /// True when the scenario configured no bounds.
    #[must_use]
    pub fn is_inert(&self) -> bool {
        self.bounds.is_empty()
    }

    /// Rows of (label, count) for display/CSV.
    #[must_use]
    pub fn rows(&self) -> Vec<(String, u64)> {
        if self.bounds.is_empty() {
            return Vec::new();
        }
        let mut rows = Vec::with_capacity(self.counts.len());
        rows.push((format!("<{}", self.bounds[0]), self.counts[0]));
        for w in self.bounds.windows(2).enumerate() {
            let (i, pair) = w;
            rows.push((format!("<{}", pair[1]), self.counts[i + 1]));
        }
        if let (Some(&last_bound), Some(&last_count)) = (self.bounds.last(), self.counts.last()) {
            rows.push((format!(">={last_bound}"), last_count));
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn moments_and_percentiles() {
        let mut h = Histogram::new();
        for v in [10, 20, 30, 40, 50] {
            h.record(ms(v));
        }
        assert_eq!(h.count(), 5);
        assert!((h.mean_ms() - 30.0).abs() < 1e-9);
        assert_eq!(h.min_ms(), 10);
        assert_eq!(h.max_ms(), 50);
        assert_eq!(h.percentile_ms(50.0), 30);
        assert_eq!(h.percentile_ms(100.0), 50);
        assert!((h.stddev_ms() - 14.142_135_623_730_951).abs() < 1e-9);
    }

    #[test]
    fn overflow_is_capped_not_lost() {
        let mut h = Histogram::new();
        h.record(Duration::from_secs(60));
        h.record(ms(5));
        assert_eq!(h.count(), 2);
        assert_eq!(h.max_ms(), 60_000);
        assert_eq!(h.percentile_ms(100.0), 10_000, "overflow reports the cap");
    }

    #[test]
    fn empty_histogram_is_all_zeroes() {
        let h = Histogram::new();
        assert_eq!(h.mean_ms(), 0.0);
        assert_eq!(h.percentile_ms(99.0), 0);
        assert_eq!(h.min_ms(), 0);
    }

    #[test]
    fn repartition_classes_match_sipp_layout() {
        let mut r = Repartition::new(&[10, 50, 100]);
        for v in [5, 9, 10, 49, 50, 99, 100, 5000] {
            r.record(ms(v));
        }
        let rows = r.rows();
        assert_eq!(rows[0], ("<10".into(), 2)); // 5, 9
        assert_eq!(rows[1], ("<50".into(), 2)); // 10, 49
        assert_eq!(rows[2], ("<100".into(), 2)); // 50, 99
        assert_eq!(rows[3], (">=100".into(), 2)); // 100, 5000
    }

    #[test]
    fn inert_repartition_stays_quiet() {
        let mut r = Repartition::new(&[]);
        r.record(ms(5));
        assert!(r.is_inert());
        assert!(r.rows().is_empty());
    }
}
