//! Pure screen rendering: `Snapshot` in, framed lines out. No terminal I/O
//! here — everything is unit-testable, and the interactive shell in
//! `terminal.rs` stays as thin as possible.

use sipr_stats::Snapshot;

use crate::style::Palette;

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

fn title_line(snap: &Snapshot, screen_name: &str, pal: &Palette) -> String {
    // The wordmark "sipr" wears the rust title color; the version and the rest
    // of the head stay default so the role tag / clock keep their exact text.
    let name = pal.paint(pal.title, "sipr");
    let head = format!(
        "{name} {} | {} [{}] | {screen_name} ",
        env!("CARGO_PKG_VERSION"),
        snap.scenario,
        if snap.uas { "UAS" } else { "UAC" },
    );
    // Dash count is computed from the VISIBLE width (escape codes are zero-
    // width), so the rule reaches the same column with or without color.
    let visible = head.len() - (name.len() - "sipr".len());
    let clock = hms(snap.elapsed);
    let dashes = WIDTH.saturating_sub(visible + clock.len() + 1);
    let rule = pal.paint(pal.label, &"-".repeat(dashes));
    format!("{head}{rule} {clock}")
}

const FOOTER: &str =
    "  [s] next screen   [+/-] rate ±1  [*//] ±10   [p] pause   [q] quit  [Q] abort";

fn footer(pal: &Palette) -> String {
    if pal.is_plain() {
        return FOOTER.to_owned();
    }
    // Tint the bracketed keys without disturbing the layout.
    let mut out = String::with_capacity(FOOTER.len() + 64);
    let mut rest = FOOTER;
    while let Some(open) = rest.find('[') {
        let Some(close) = rest[open..].find(']') else {
            break;
        };
        out.push_str(&rest[..open + 1]);
        out.push_str(&pal.paint(pal.key, &rest[open + 1..open + close]));
        out.push(']');
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    out
}

/// Render the selected screen as plain lines (no ANSI codes).
#[must_use]
pub fn render(snap: &Snapshot, screen: Screen) -> Vec<String> {
    render_with(snap, screen, &Palette::PLAIN)
}

/// Render the selected screen, styling with `pal` (use [`Palette::COLOR`] for
/// the Ferrous look, [`Palette::PLAIN`] for no escapes).
#[must_use]
pub fn render_with(snap: &Snapshot, screen: Screen, pal: &Palette) -> Vec<String> {
    let mut lines = match screen {
        Screen::Main => render_main(snap, pal),
        Screen::Scenario => render_scenario(snap, pal),
        Screen::Repartition => render_repartition(snap, pal),
    };
    lines.push(String::new());
    lines.push(footer(pal));
    lines
}

fn render_main(snap: &Snapshot, pal: &Palette) -> Vec<String> {
    let mut out = vec![title_line(snap, "main", pal), String::new()];
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
    let ok = pal.paint(pal.ok, &format!("{:>8}", snap.successful));
    let failed = if snap.failed > 0 {
        pal.paint(pal.bad, &format!("{:>7}", snap.failed))
    } else {
        format!("{:>7}", snap.failed)
    };
    out.push(format!(
        "  Calls:    {:>8} created   {:>7} live   {ok} ok   {failed} failed",
        snap.created, snap.live
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
    if snap.rtp_streams_started > 0 {
        #[allow(clippy::cast_precision_loss)]
        let kb = snap.rtp_bytes_sent as f64 / 1024.0;
        out.push(format!(
            "  RTP:      {:>8} streams   {:>8} pckts sent   {kb:>9.1} kB",
            snap.rtp_streams_started, snap.rtp_packets_sent
        ));
    }
    if snap.rtp_check_ok + snap.rtp_check_failed > 0 {
        out.push(format!(
            "  RTP check: {:>7} passed   {:>8} failed",
            snap.rtp_check_ok, snap.rtp_check_failed
        ));
    }
    if snap.rtp_echo_packets + snap.rtp_echo2_packets > 0 {
        out.push(format!(
            "  RTP echo: {:>8} pckts 1st stream   {:>8} pckts 2nd stream",
            snap.rtp_echo_packets, snap.rtp_echo2_packets
        ));
    }
    out.push(String::new());
    for r in &snap.rtds {
        let tag = pal.paint(pal.label, &format!("RTD {:<4}", r.name));
        out.push(format!(
            "  {tag} n={:<8} avg {:>8.1}ms   sd {:>7.1}ms   p99 {:>6}ms   max {:>6}ms",
            r.count, r.mean_ms, r.stddev_ms, r.p99_ms, r.max_ms
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

fn render_scenario(snap: &Snapshot, pal: &Palette) -> Vec<String> {
    let mut out = vec![title_line(snap, "scenario", pal), String::new()];
    out.push(pal.paint(
        pal.label,
        &format!(
            "  {:>3}  {:<22} {:>9} {:>9} {:>8} {:>8} {:>8}",
            "#", "step", "sent", "recv", "retrans", "timeout", "unexp"
        ),
    ));
    out.push(pal.paint(pal.label, &format!("  {}", "-".repeat(WIDTH - 4))));
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

fn render_repartition(snap: &Snapshot, pal: &Palette) -> Vec<String> {
    let mut out = vec![title_line(snap, "repartitions", pal), String::new()];
    let table = |title: &str, rows: &[(String, u64)], out: &mut Vec<String>| {
        out.push(pal.paint(pal.label, &format!("  {title}")));
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
    fn main_screen_shows_rtp_only_when_media_ran() {
        let quiet = render(&snap(), Screen::Main).join("\n");
        assert!(!quiet.contains("RTP:"), "{quiet}");
        let mut s = snap();
        s.rtp_streams_started = 3;
        s.rtp_packets_sent = 1200;
        s.rtp_bytes_sent = 2048;
        let all = render(&s, Screen::Main).join("\n");
        assert!(all.contains("3 streams"), "{all}");
        assert!(all.contains("1200 pckts sent"), "{all}");
        assert!(all.contains("2.0 kB"), "{all}");
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

    #[test]
    fn color_palette_wraps_the_brand_accents() {
        let color = render_with(&snap(), Screen::Main, &Palette::COLOR).join("\n");
        // Rust title on the wordmark, sage on the ok count, a reset somewhere.
        assert!(
            color.contains("\x1b[1;38;5;208msipr"),
            "title color: {color:?}"
        );
        assert!(color.contains("\x1b[38;5;65m"), "sage ok count missing");
        assert!(color.contains("\x1b[0m"), "reset missing");
        // The plain path stays escape-free.
        let plain = render(&snap(), Screen::Main).join("\n");
        assert!(!plain.contains('\x1b'), "plain must have no escapes");
    }

    #[test]
    fn colored_title_rule_reaches_the_same_width_as_plain() {
        // Escape codes are zero-width; the visible clock must still align.
        let plain = title_line(&snap(), "main", &Palette::PLAIN);
        let color = title_line(&snap(), "main", &Palette::COLOR);
        let strip = |s: &str| {
            let mut out = String::new();
            let mut in_esc = false;
            for c in s.chars() {
                if c == '\x1b' {
                    in_esc = true;
                } else if in_esc {
                    if c == 'm' {
                        in_esc = false;
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        assert_eq!(strip(&color), plain, "visible text must match plain");
    }
}
