//! UDP retransmission schedule: RFC 3261 T1/T2 shape, SIPp-style knobs.
//!
//! T1 = 500 ms initial, doubling per attempt, capped at T2 = 4 s. The
//! scenario's `retrans="N"` attribute overrides the base interval; the global
//! `-max_retrans` caps attempts; `-nr` disables retransmission entirely.

use std::time::Duration;

/// RFC 3261 T1: default initial retransmission interval.
pub const T1: Duration = Duration::from_millis(500);
/// RFC 3261 T2: retransmission interval cap.
pub const T2: Duration = Duration::from_millis(4000);
/// Default attempt cap (SIPp's default max_udp_retrans is 5 for requests).
pub const DEFAULT_MAX_RETRANS: u32 = 5;

/// Immutable retransmission plan for one sent message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransSchedule {
    base: Duration,
    max_retrans: u32,
    enabled: bool,
}

impl RetransSchedule {
    /// Plan with SIPp defaults, honoring a per-send `retrans` override,
    /// a global max-retrans cap, and the `-nr` kill switch.
    #[must_use]
    pub fn new(base_override_ms: Option<u64>, max_retrans: Option<u32>, no_retrans: bool) -> Self {
        Self {
            base: base_override_ms.map_or(T1, Duration::from_millis),
            max_retrans: max_retrans.unwrap_or(DEFAULT_MAX_RETRANS),
            enabled: !no_retrans && base_override_ms != Some(0),
        }
    }

    /// Schedule for a send with no `retrans` attribute at all: SIPp does not
    /// retransmit such messages (retransmission is opt-in per `<send>`).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            base: T1,
            max_retrans: 0,
            enabled: false,
        }
    }

    /// Interval before retransmission `attempt` (1-based), or `None` when the
    /// message should not be retransmitted (again).
    #[must_use]
    pub fn interval(&self, attempt: u32) -> Option<Duration> {
        if !self.enabled || attempt == 0 || attempt > self.max_retrans {
            return None;
        }
        // attempt 1 → base, 2 → base*2, ... capped at T2.
        let factor = 1u32 << (attempt - 1).min(16);
        Some(self.base.saturating_mul(factor).min(T2.max(self.base)))
    }

    /// Total attempts this plan allows.
    #[must_use]
    pub fn max_attempts(&self) -> u32 {
        if self.enabled { self.max_retrans } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn default_schedule_doubles_and_caps_at_t2() {
        let s = RetransSchedule::new(Some(500), None, false);
        let intervals: Vec<_> = (1..=5).filter_map(|a| s.interval(a)).collect();
        assert_eq!(
            intervals,
            vec![ms(500), ms(1000), ms(2000), ms(4000), ms(4000)]
        );
        assert_eq!(s.interval(6), None, "default cap is 5 attempts");
    }

    #[test]
    fn base_override_changes_the_ladder() {
        let s = RetransSchedule::new(Some(100), Some(7), false);
        assert_eq!(s.interval(1), Some(ms(100)));
        assert_eq!(s.interval(2), Some(ms(200)));
        assert_eq!(s.interval(6), Some(ms(3200)));
        assert_eq!(s.interval(7), Some(ms(4000)), "capped at T2");
        assert_eq!(s.interval(8), None);
    }

    #[test]
    fn base_above_t2_is_respected() {
        // SIPp allows retrans="5000"; the cap must not shrink the base.
        let s = RetransSchedule::new(Some(5000), Some(2), false);
        assert_eq!(s.interval(1), Some(ms(5000)));
        assert_eq!(s.interval(2), Some(ms(5000)));
    }

    #[test]
    fn no_retrans_disables_everything() {
        let s = RetransSchedule::new(Some(500), None, true);
        assert_eq!(s.interval(1), None);
        assert_eq!(s.max_attempts(), 0);
        assert_eq!(RetransSchedule::disabled().interval(1), None);
        // retrans="0" means "do not retransmit this send" in SIPp.
        assert_eq!(RetransSchedule::new(Some(0), None, false).interval(1), None);
    }

    #[test]
    fn huge_attempt_numbers_do_not_overflow() {
        let s = RetransSchedule::new(Some(500), Some(u32::MAX), false);
        assert_eq!(s.interval(40), Some(ms(4000)));
        assert_eq!(s.interval(u32::MAX), Some(ms(4000)));
    }
}
