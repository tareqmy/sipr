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
/// SIPp's default retransmission counts: `UDP_MAX_RETRANS_INVITE_TRANSACTION`
/// and `UDP_MAX_RETRANS_NON_INVITE_TRANSACTION` (`call.hpp`).
pub const DEFAULT_MAX_INVITE_RETRANS: u32 = 5;
/// See [`DEFAULT_MAX_INVITE_RETRANS`].
pub const DEFAULT_MAX_NON_INVITE_RETRANS: u32 = 9;

/// The retransmission caps: `-max_invite_retrans`, `-max_non_invite_retrans`
/// and the global `-max_retrans`, which SIPp applies as a ceiling on both
/// (`call.cpp`: `min(bInviteTransaction ? max_invite_retrans :
/// max_non_invite_retrans, max_udp_retrans)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransCaps {
    /// Retransmissions of an INVITE before the call fails.
    pub invite: u32,
    /// Retransmissions of any other message before the call fails.
    pub non_invite: u32,
    /// `-max_retrans`: a ceiling on both, when given.
    pub global: Option<u32>,
}

impl Default for RetransCaps {
    fn default() -> Self {
        Self {
            invite: DEFAULT_MAX_INVITE_RETRANS,
            non_invite: DEFAULT_MAX_NON_INVITE_RETRANS,
            global: None,
        }
    }
}

/// Immutable retransmission plan for one sent message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransSchedule {
    base: Duration,
    max_retrans: u32,
    enabled: bool,
    /// An INVITE's timer keeps doubling past T2 (SIPp caps only
    /// non-INVITE transactions at `global_t2`).
    invite: bool,
}

impl RetransSchedule {
    /// Plan with SIPp's schedule, honoring a per-send `retrans` override,
    /// the caps for an INVITE or other message, and the `-nr` kill switch.
    #[must_use]
    pub fn new(
        base_override_ms: Option<u64>,
        invite: bool,
        caps: RetransCaps,
        no_retrans: bool,
    ) -> Self {
        let kind_cap = if invite { caps.invite } else { caps.non_invite };
        Self {
            base: base_override_ms.map_or(T1, Duration::from_millis),
            max_retrans: kind_cap.min(caps.global.unwrap_or(u32::MAX)),
            enabled: !no_retrans && base_override_ms != Some(0),
            invite,
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
            invite: false,
        }
    }

    /// Interval before retransmission `attempt` (1-based), or `None` when the
    /// message should not be retransmitted (again).
    #[must_use]
    pub fn interval(&self, attempt: u32) -> Option<Duration> {
        if !self.enabled || attempt == 0 || attempt > self.max_retrans {
            return None;
        }
        // attempt 1 → base, 2 → base*2, ...; non-INVITE capped at T2, an
        // INVITE keeps doubling (SIPp `nb_last_delay *= 2` with the T2 cap
        // applied only when `!bInviteTransaction`).
        let factor = 1u32 << (attempt - 1).min(16);
        let interval = self.base.saturating_mul(factor);
        if self.invite {
            Some(interval)
        } else {
            Some(interval.min(T2.max(self.base)))
        }
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
    fn non_invite_doubles_caps_at_t2_and_allows_nine() {
        let s = RetransSchedule::new(Some(500), false, RetransCaps::default(), false);
        let intervals: Vec<_> = (1..=9).filter_map(|a| s.interval(a)).collect();
        assert_eq!(
            intervals,
            vec![
                ms(500),
                ms(1000),
                ms(2000),
                ms(4000),
                ms(4000),
                ms(4000),
                ms(4000),
                ms(4000),
                ms(4000)
            ]
        );
        assert_eq!(s.interval(10), None, "SIPp's non-INVITE cap is 9");
    }

    #[test]
    fn invite_keeps_doubling_and_allows_five() {
        let s = RetransSchedule::new(Some(500), true, RetransCaps::default(), false);
        let intervals: Vec<_> = (1..=5).filter_map(|a| s.interval(a)).collect();
        assert_eq!(
            intervals,
            vec![ms(500), ms(1000), ms(2000), ms(4000), ms(8000)]
        );
        assert_eq!(s.interval(6), None, "SIPp's INVITE cap is 5");
    }

    #[test]
    fn caps_can_be_set_and_the_global_one_is_a_ceiling() {
        let caps = RetransCaps {
            invite: 2,
            non_invite: 7,
            global: Some(3),
        };
        assert_eq!(
            RetransSchedule::new(Some(500), true, caps, false).max_attempts(),
            2
        );
        assert_eq!(
            RetransSchedule::new(Some(500), false, caps, false).max_attempts(),
            3
        );
        let s = RetransSchedule::new(
            Some(100),
            false,
            RetransCaps {
                global: Some(7),
                ..RetransCaps::default()
            },
            false,
        );
        assert_eq!(s.interval(1), Some(ms(100)));
        assert_eq!(s.interval(2), Some(ms(200)));
        assert_eq!(s.interval(6), Some(ms(3200)));
        assert_eq!(s.interval(7), Some(ms(4000)), "capped at T2");
        assert_eq!(s.interval(8), None);
    }

    #[test]
    fn base_above_t2_is_respected() {
        // SIPp allows retrans="5000"; the cap must not shrink the base.
        let caps = RetransCaps {
            global: Some(2),
            ..RetransCaps::default()
        };
        let s = RetransSchedule::new(Some(5000), false, caps, false);
        assert_eq!(s.interval(1), Some(ms(5000)));
        assert_eq!(s.interval(2), Some(ms(5000)));
    }

    #[test]
    fn no_retrans_disables_everything() {
        let s = RetransSchedule::new(Some(500), false, RetransCaps::default(), true);
        assert_eq!(s.interval(1), None);
        assert_eq!(s.max_attempts(), 0);
        assert_eq!(RetransSchedule::disabled().interval(1), None);
        // retrans="0" means "do not retransmit this send" in SIPp.
        assert_eq!(
            RetransSchedule::new(Some(0), false, RetransCaps::default(), false).interval(1),
            None
        );
    }

    #[test]
    fn huge_attempt_numbers_do_not_overflow() {
        let caps = RetransCaps {
            global: Some(u32::MAX),
            non_invite: u32::MAX,
            ..RetransCaps::default()
        };
        let s = RetransSchedule::new(Some(500), false, caps, false);
        assert_eq!(s.interval(40), Some(ms(4000)));
        assert_eq!(s.interval(u32::MAX), Some(ms(4000)));
    }
}
