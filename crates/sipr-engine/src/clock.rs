//! Wall-clock text for `[date]` and `[timestamp]` (docs/SIPP_COMPAT.md §6
//! M39), in UTC, with no dependency: a proleptic-Gregorian civil-date
//! conversion (Howard Hinnant's `civil_from_days`) over `SystemTime`.
//!
//! SIPp renders `[date]` from `gmtime` and `[timestamp]` from `localtime`;
//! sipr uses UTC for both, so a `[timestamp]` differs from SIPp's by the
//! host's zone offset (and carries `Z` where SIPp writes the offset).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Broken-down UTC time.
struct Civil {
    year: i64,
    month: u32,
    day: u32,
    /// 0 = Sunday.
    weekday: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Seconds and microseconds since the epoch (a pre-epoch clock reads 0).
fn unix_parts(t: SystemTime) -> (i64, u32) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    (
        i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        d.subsec_micros(),
    )
}

/// Civil UTC time of a unix second count.
fn civil(secs: i64) -> Civil {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil_from_days: days since 1970-01-01 → (y, m, d).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Civil {
        year,
        month: m as u32,
        day: d as u32,
        weekday: (days + 4).rem_euclid(7) as u32, // 1970-01-01 was a Thursday
        hour: (rem / 3600) as u32,
        minute: (rem % 3600 / 60) as u32,
        second: (rem % 60) as u32,
    }
}

/// `[date]`: RFC 1123 / RFC 2822 form as SIPp writes it,
/// `Mon, 25 Oct 2021 07:20:55 GMT` (`strftime("%a, %d %b %Y %T GMT")`).
#[must_use]
pub fn rfc1123_date(t: SystemTime) -> String {
    let (secs, _) = unix_parts(t);
    let c = civil(secs);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[c.weekday as usize],
        c.day,
        MONTHS[(c.month - 1) as usize],
        c.year,
        c.hour,
        c.minute,
        c.second
    )
}

/// `[timestamp]`: SIPp's log time (`CStat::formatTime`). With `rfc3339`,
/// `2021-10-25T07:20:55.123456Z`; otherwise the tab-separated
/// `2021-10-25<TAB>07:20:55.123456<TAB>1635146455.123456`, the epoch
/// seconds zero-padded to ten digits as SIPp's `%10.10ld`.
#[must_use]
pub fn sipp_timestamp(t: SystemTime, rfc3339: bool) -> String {
    let (secs, micros) = unix_parts(t);
    let c = civil(secs);
    if rfc3339 {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second, micros
        )
    } else {
        format!(
            "{:04}-{:02}-{:02}\t{:02}:{:02}:{:02}.{:06}\t{:010}.{:06}",
            c.year, c.month, c.day, c.hour, c.minute, c.second, micros, secs, micros
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64, micros: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(secs, micros * 1000)
    }

    #[test]
    fn date_matches_sipps_documented_example() {
        // SIPp's keywords.rst example for [date].
        assert_eq!(
            rfc1123_date(at(1_635_146_455, 0)),
            "Mon, 25 Oct 2021 07:20:55 GMT"
        );
        assert_eq!(rfc1123_date(at(0, 0)), "Thu, 01 Jan 1970 00:00:00 GMT");
        // A leap day and a year boundary.
        assert_eq!(
            rfc1123_date(at(951_782_400, 0)),
            "Tue, 29 Feb 2000 00:00:00 GMT"
        );
        assert_eq!(
            rfc1123_date(at(1_704_067_199, 0)),
            "Sun, 31 Dec 2023 23:59:59 GMT"
        );
    }

    #[test]
    fn timestamp_has_sipps_two_shapes() {
        assert_eq!(
            sipp_timestamp(at(1_635_146_455, 123_456), true),
            "2021-10-25T07:20:55.123456Z"
        );
        assert_eq!(
            sipp_timestamp(at(1_635_146_455, 123_456), false),
            "2021-10-25\t07:20:55.123456\t1635146455.123456"
        );
        assert_eq!(
            sipp_timestamp(at(0, 7), false),
            "1970-01-01\t00:00:00.000007\t0000000000.000007"
        );
    }
}
