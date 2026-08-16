//! Pure screen rendering: `Snapshot` in, framed lines out. No terminal I/O
//! here — everything is unit-testable, and the interactive shell in
//! `terminal.rs` stays as thin as possible.

use sipr_stats::Snapshot;

/// Which screen is showing ('s' cycles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Rates, call counts, message counters, RTDs.
    Main,
    /// Per-step table.
    Scenario,
    /// Repartition tables.
    Repartition,
}

impl Screen {
    /// The next screen in the cycle.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Main => Self::Scenario,
            Self::Scenario => Self::Repartition,
            Self::Repartition => Self::Main,
        }
    }
}

const WIDTH: usize = 78;

fn hms(d: std::time::Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn title_line(snap: &Snapshot, screen_name: &str) -> String {
    let head = format!(
        "sipr {} | {} [{}] | {screen_name} ",
        env!("CARGO_PKG_VERSION"),
        snap.scenario,
        if snap.uas { "UAS" } else { "UAC" },
    );
    let clock = hms(snap.elapsed);
    let dashes = WIDTH.saturating_sub(head.len() + clock.len() + 1);
    format!("{head}{} {clock}", "-".repeat(dashes))
}

const FOOTER: &str =
    "  [s] next screen   [+/-] rate ±1  [*//] ±10   [p] pause   [q] quit  [Q] abort";

/// Render the selected screen as plain lines (no ANSI codes).
#[must_use]
pub fn render(snap: &Snapshot, screen: Screen) -> Vec<String> {
    let mut lines = match screen {
        Screen::Main => render_main(snap),
        Screen::Scenario => render_scenario(snap),
        Screen::Repartition => render_repartition(snap),
    };
    lines.push(String::new());
    lines.push(FOOTER.to_owned());
    lines
}

fn render_main(snap: &Snapshot) -> Vec<String> {
    let mut out = vec![title_line(snap, "main"), String::new()];
    let paused = if snap.paused { "  ** PAUSED **" } else { "" };
    if snap.uas {
        out.push(format!(
            "  Incoming traffic (rate {:.1} cps period, {:.1} cps avg){paused}",
            snap.rate_period, snap.rate_cumulative
        ));
    } else {
        out.push(format!(
            "  Call rate: target {:.1}, period {:.1} cps, avg {:.1} cps{paused}",
            snap.rate_target, snap.rate_period, snap.rate_cumulative
        ));
    }
    out.push(String::new());
    out.push(format!(
        "  Calls:    {:>8} created   {:>7} live   {:>8} ok   {:>7} failed",
        snap.created, snap.live, snap.successful, snap.failed
    ));
    out.push(format!(
        "  Messages: {:>8} sent   {:>8} matched   {:>5}/{:<5} retrans out/in",
        snap.messages_sent, snap.messages_matched, snap.retrans_sent, snap.retrans_recv
    ));
    out.push(format!(
        "  Other:    {:>8} unexpected   {:>6} garbage   {:>6} auto-answered",
        snap.unexpected, snap.garbage, snap.auto_answered
    ));
    if snap.failed > 0 {
        out.push(format!(
            "  Failures: {} unexpected, {} timeout, {} retrans-exhausted, {} other",
            snap.failed_unexpected, snap.failed_timeout, snap.failed_retrans, snap.failed_other
        ));
    }
    out.push(String::new());
    for r in &snap.rtds {
        out.push(format!(
            "  RTD {:<4} n={:<8} avg {:>8.1}ms   sd {:>7.1}ms   p99 {:>6}ms   max {:>6}ms",
            r.name, r.count, r.mean_ms, r.stddev_ms, r.p99_ms, r.max_ms
        ));
    }
    let (n, mean, max) = snap.call_length;
    if n > 0 {
        out.push(format!(
            "  Call length: n={n}   avg {mean:>8.1}ms   max {max:>6}ms"
        ));
    }
    out
}

fn render_scenario(snap: &Snapshot) -> Vec<String> {
    let mut out = vec![title_line(snap, "scenario"), String::new()];
    out.push(format!(
        "  {:>3}  {:<22} {:>9} {:>9} {:>8} {:>8} {:>8}",
        "#", "step", "sent", "recv", "retrans", "timeout", "unexp"
    ));
    out.push(format!("  {}", "-".repeat(WIDTH - 4)));
    for (i, row) in snap.steps.iter().enumerate() {
        let s = &row.stats;
        out.push(format!(
            "  {i:>3}  {:<22} {:>9} {:>9} {:>8} {:>8} {:>8}",
            truncate(&row.label, 22),
            s.sent,
            s.recv,
            s.retrans,
            s.timeouts,
            s.unexpected
        ));
    }
    out
}

fn render_repartition(snap: &Snapshot) -> Vec<String> {
    let mut out = vec![title_line(snap, "repartitions"), String::new()];
    let table = |title: &str, rows: &[(String, u64)], out: &mut Vec<String>| {
        out.push(format!("  {title}"));
        if rows.is_empty() {
            out.push("    (not configured in this scenario)".to_owned());
        } else {
            for (label, count) in rows {
                out.push(format!("    {label:<12} {count:>10}"));
            }
        }
        out.push(String::new());
    };
    table(
        "Response time repartition (ms, RTD 1)",
        &snap.response_rows,
        &mut out,
    );
    table(
        "Call length repartition (ms)",
        &snap.call_length_rows,
        &mut out,
    );
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sipr_stats::{RtdRow, StepRow, StepStats};

    fn snap() -> Snapshot {
        Snapshot {
            scenario: "Basic Sipstone UAC".into(),
            uas: false,
            elapsed: std::time::Duration::from_secs(3723),
            live: 12,
            rate_target: 50.0,
            rate_period: 49.5,
            rate_cumulative: 49.9,
            paused: false,
            created: 1000,
            successful: 950,
            failed: 38,
            failed_unexpected: 8,
            failed_timeout: 30,
            messages_sent: 3000,
            messages_matched: 2950,
            retrans_sent: 5,
            retrans_recv: 3,
            unexpected: 8,
            rtds: vec![RtdRow {
                name: "1".into(),
                count: 950,
                mean_ms: 12.5,
                stddev_ms: 3.1,
                p99_ms: 22,
                max_ms: 40,
            }],
            call_length: (950, 3100.0, 4000),
            response_rows: vec![("<10".into(), 100), (">=200".into(), 3)],
            call_length_rows: vec![],
            steps: vec![
                StepRow {
                    label: "send INVITE".into(),
                    stats: StepStats {
                        sent: 1000,
                        retrans: 5,
                        ..Default::default()
                    },
                },
                StepRow {
                    label: "recv 200".into(),
                    stats: StepStats {
                        recv: 950,
                        timeouts: 30,
                        ..Default::default()
                    },
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn main_screen_shows_the_essentials() {
        let lines = render(&snap(), Screen::Main);
        let all = lines.join("\n");
        assert!(all.contains("01:02:03"), "{all}");
        assert!(all.contains("target 50.0, period 49.5"), "{all}");
        assert!(all.contains("1000 created"), "{all}");
        assert!(all.contains("950 ok"), "{all}");
        assert!(all.contains("RTD 1"), "{all}");
        assert!(all.contains("30 timeout"), "{all}");
        assert!(all.contains("[q] quit"), "{all}");
    }

    #[test]
    fn scenario_screen_tabulates_steps() {
        let lines = render(&snap(), Screen::Scenario);
        let all = lines.join("\n");
        assert!(all.contains("send INVITE"), "{all}");
        assert!(all.contains("recv 200"), "{all}");
        // The INVITE row carries its sent + retrans counters.
        let invite = lines.iter().find(|l| l.contains("send INVITE")).unwrap();
        assert!(invite.contains("1000"), "{invite}");
        assert!(invite.contains('5'), "{invite}");
    }

    #[test]
    fn repartition_screen_renders_rows_and_placeholders() {
        let lines = render(&snap(), Screen::Repartition);
        let all = lines.join("\n");
        assert!(all.contains("<10"), "{all}");
        assert!(all.contains("not configured"), "{all}");
    }

    #[test]
    fn screens_cycle() {
        assert_eq!(Screen::Main.next(), Screen::Scenario);
        assert_eq!(Screen::Scenario.next(), Screen::Repartition);
        assert_eq!(Screen::Repartition.next(), Screen::Main);
    }

    #[test]
    fn paused_flag_is_visible() {
        let mut s = snap();
        s.paused = true;
        let all = render(&s, Screen::Main).join("\n");
        assert!(all.contains("** PAUSED **"), "{all}");
    }

    #[test]
    fn uas_snapshot_renders_incoming_header() {
        let mut s = snap();
        s.uas = true;
        let all = render(&s, Screen::Main).join("\n");
        assert!(all.contains("Incoming traffic"), "{all}");
        assert!(all.contains("[UAS]"), "{all}");
    }
}
