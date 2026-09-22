//! The statistics snapshot in Prometheus' text exposition format, served at
//! `GET /metrics`.
//!
//! In-tree by the same policy as [`crate::json`]: the format is a handful of
//! lines of text and the alternative is a client library with a registry, a
//! global collector and a dependency tree, none of which sipr needs to print
//! counters it already has.
//!
//! Conventions followed, because scrapers and dashboards rely on them:
//! every name is prefixed `sipr_`, cumulative counters end in `_total` and
//! are typed `counter`, point-in-time values are `gauge`, durations are in
//! the base unit Prometheus expects (seconds, not milliseconds), and what
//! would otherwise be several near-identical metric names is one metric with
//! a label — failures by `reason`, per-step counters by `step`.

use std::fmt::Write as _;

use sipr_stats::Snapshot;

/// Render `s` as a Prometheus exposition document.
#[must_use]
pub fn render(s: &Snapshot) -> String {
    let mut out = String::with_capacity(4096);
    let role = if s.uas { "UAS" } else { "UAC" };

    // An info metric carries the run's identity, so the counters below stay
    // free of high-cardinality labels (the standard `_info` pattern).
    metric(
        &mut out,
        "sipr_run_info",
        "gauge",
        "Run identity: always 1, labelled with the scenario and role.",
    );
    let _ = writeln!(
        out,
        "sipr_run_info{{scenario=\"{}\",role=\"{role}\",display=\"{}\"}} 1",
        escape(&s.scenario),
        escape(s.display.label())
    );

    metric(
        &mut out,
        "sipr_elapsed_seconds",
        "gauge",
        "Wall-clock time since the run started.",
    );
    let _ = writeln!(out, "sipr_elapsed_seconds {:.3}", s.elapsed.as_secs_f64());

    metric(
        &mut out,
        "sipr_calls_active",
        "gauge",
        "Calls in flight right now.",
    );
    let _ = writeln!(out, "sipr_calls_active {}", s.live);

    metric(
        &mut out,
        "sipr_call_rate_cps",
        "gauge",
        "Call rate in calls per second: target, the last period, and the whole run.",
    );
    let _ = writeln!(
        out,
        "sipr_call_rate_cps{{window=\"target\"}} {}",
        s.rate_target
    );
    let _ = writeln!(
        out,
        "sipr_call_rate_cps{{window=\"period\"}} {}",
        s.rate_period
    );
    let _ = writeln!(
        out,
        "sipr_call_rate_cps{{window=\"cumulative\"}} {}",
        s.rate_cumulative
    );

    metric(
        &mut out,
        "sipr_paused",
        "gauge",
        "1 while traffic generation is paused.",
    );
    let _ = writeln!(out, "sipr_paused {}", u8::from(s.paused));

    metric(
        &mut out,
        "sipr_calls_created_total",
        "counter",
        "Calls started since the run began.",
    );
    let _ = writeln!(out, "sipr_calls_created_total {}", s.created);

    metric(
        &mut out,
        "sipr_calls_successful_total",
        "counter",
        "Calls that reached the end of the scenario.",
    );
    let _ = writeln!(out, "sipr_calls_successful_total {}", s.successful);

    // One metric with a `reason` label rather than four names: a dashboard
    // can then sum without knowing the breakdown, and still split by reason.
    metric(
        &mut out,
        "sipr_calls_failed_total",
        "counter",
        "Failed calls by cause.",
    );
    for (reason, value) in [
        ("unexpected_message", s.failed_unexpected),
        ("recv_timeout", s.failed_timeout),
        ("max_retrans", s.failed_retrans),
        ("other", s.failed_other),
    ] {
        let _ = writeln!(
            out,
            "sipr_calls_failed_total{{reason=\"{reason}\"}} {value}"
        );
    }

    metric(
        &mut out,
        "sipr_messages_total",
        "counter",
        "SIP messages by kind.",
    );
    for (kind, value) in [
        ("sent", s.messages_sent),
        ("matched", s.messages_matched),
        ("retrans_sent", s.retrans_sent),
        ("retrans_recv", s.retrans_recv),
        ("auto_answered", s.auto_answered),
        ("unexpected", s.unexpected),
        ("garbage", s.garbage),
    ] {
        let _ = writeln!(out, "sipr_messages_total{{kind=\"{kind}\"}} {value}");
    }

    rtp_metrics(&mut out, s);
    rtd_metrics(&mut out, s);
    step_metrics(&mut out, s);
    out
}

/// Media counters. Emitted always: a scrape whose series appear and vanish
/// with the scenario is worse to alert on than a run of zeros.
fn rtp_metrics(out: &mut String, s: &Snapshot) {
    metric(
        out,
        "sipr_rtp_packets_total",
        "counter",
        "RTP datagrams by direction and role.",
    );
    for (kind, value) in [
        ("sent", s.rtp_packets_sent),
        ("echoed_audio", s.rtp_echo_packets),
        ("echoed_video", s.rtp_echo2_packets),
    ] {
        let _ = writeln!(out, "sipr_rtp_packets_total{{kind=\"{kind}\"}} {value}");
    }

    metric(
        out,
        "sipr_rtp_bytes_total",
        "counter",
        "RTP payload bytes by direction.",
    );
    for (kind, value) in [
        ("sent", s.rtp_bytes_sent),
        ("received", s.rtp_bytes_received),
    ] {
        let _ = writeln!(out, "sipr_rtp_bytes_total{{kind=\"{kind}\"}} {value}");
    }

    metric(
        out,
        "sipr_rtp_checks_total",
        "counter",
        "Echo checks on generated RTP streams, by outcome.",
    );
    let _ = writeln!(
        out,
        "sipr_rtp_checks_total{{outcome=\"ok\"}} {}",
        s.rtp_check_ok
    );
    let _ = writeln!(
        out,
        "sipr_rtp_checks_total{{outcome=\"failed\"}} {}",
        s.rtp_check_failed
    );

    metric(
        out,
        "sipr_rtp_streams_started_total",
        "counter",
        "Media replays started.",
    );
    let _ = writeln!(
        out,
        "sipr_rtp_streams_started_total {}",
        s.rtp_streams_started
    );
}

/// Response-time distributions, one series per RTD, plus call length.
fn rtd_metrics(out: &mut String, s: &Snapshot) {
    if !s.rtds.is_empty() {
        metric(
            out,
            "sipr_rtd_seconds",
            "gauge",
            "Response-time distribution summary per RTD.",
        );
        for r in &s.rtds {
            let name = escape(&r.name);
            let _ = writeln!(
                out,
                "sipr_rtd_seconds{{rtd=\"{name}\",stat=\"mean\"}} {:.6}",
                r.mean_ms / 1000.0
            );
            let _ = writeln!(
                out,
                "sipr_rtd_seconds{{rtd=\"{name}\",stat=\"stddev\"}} {:.6}",
                r.stddev_ms / 1000.0
            );
            #[allow(clippy::cast_precision_loss)]
            let _ = writeln!(
                out,
                "sipr_rtd_seconds{{rtd=\"{name}\",stat=\"p99\"}} {:.6}",
                r.p99_ms as f64 / 1000.0
            );
            #[allow(clippy::cast_precision_loss)]
            let _ = writeln!(
                out,
                "sipr_rtd_seconds{{rtd=\"{name}\",stat=\"max\"}} {:.6}",
                r.max_ms as f64 / 1000.0
            );
        }

        metric(
            out,
            "sipr_rtd_samples_total",
            "counter",
            "Response times recorded per RTD.",
        );
        for r in &s.rtds {
            let _ = writeln!(
                out,
                "sipr_rtd_samples_total{{rtd=\"{}\"}} {}",
                escape(&r.name),
                r.count
            );
        }
    }

    let (count, mean_ms, max_ms) = s.call_length;
    metric(
        out,
        "sipr_call_length_seconds",
        "gauge",
        "Call length summary.",
    );
    let _ = writeln!(
        out,
        "sipr_call_length_seconds{{stat=\"mean\"}} {:.6}",
        mean_ms / 1000.0
    );
    #[allow(clippy::cast_precision_loss)]
    let _ = writeln!(
        out,
        "sipr_call_length_seconds{{stat=\"max\"}} {:.6}",
        max_ms as f64 / 1000.0
    );
    metric(
        out,
        "sipr_call_length_samples_total",
        "counter",
        "Calls whose length was recorded.",
    );
    let _ = writeln!(out, "sipr_call_length_samples_total {count}");
}

/// Per-step counters, labelled by index and the screen's own label. The
/// index keeps the series stable when a label is edited; the label keeps a
/// dashboard readable.
fn step_metrics(out: &mut String, s: &Snapshot) {
    if s.steps.is_empty() {
        return;
    }
    metric(
        out,
        "sipr_step_messages_total",
        "counter",
        "Per-scenario-step message counters.",
    );
    for (index, row) in s.steps.iter().enumerate() {
        let label = escape(&row.label);
        for (kind, value) in [
            ("sent", row.stats.sent),
            ("recv", row.stats.recv),
            ("retrans", row.stats.retrans),
            ("timeouts", row.stats.timeouts),
            ("unexpected", row.stats.unexpected),
        ] {
            let _ = writeln!(
                out,
                "sipr_step_messages_total{{step=\"{index}\",label=\"{label}\",kind=\"{kind}\"}} \
                 {value}"
            );
        }
    }
}

/// The `# HELP` and `# TYPE` pair every metric family needs.
fn metric(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Escape a label value: backslash, double quote and newline, per the
/// exposition format. A scenario name or step label is free text, so this is
/// not optional — an unescaped quote would corrupt every following series.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sipr_stats::{RtdRow, StepRow, StepStats};

    fn snap() -> Snapshot {
        Snapshot {
            scenario: "uac".into(),
            created: 7,
            successful: 5,
            failed: 2,
            failed_timeout: 2,
            live: 3,
            rate_target: 10.0,
            steps: vec![StepRow {
                label: "send INVITE".into(),
                hidden: false,
                stats: StepStats {
                    sent: 7,
                    ..Default::default()
                },
            }],
            rtds: vec![RtdRow {
                name: "1".into(),
                count: 5,
                mean_ms: 12.5,
                stddev_ms: 1.0,
                p99_ms: 20,
                max_ms: 25,
            }],
            ..Default::default()
        }
    }

    /// Every series line must belong to a family that declared `# TYPE`
    /// before it, which is the rule a scraper enforces.
    #[test]
    fn every_series_has_a_preceding_type_declaration() {
        let text = render(&snap());
        let mut declared: Vec<String> = Vec::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, kind) = rest.split_once(' ').expect("TYPE name and kind");
                assert!(
                    matches!(kind, "counter" | "gauge"),
                    "unexpected metric type: {kind}"
                );
                declared.push(name.to_owned());
                continue;
            }
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let name = line
                .split(['{', ' '])
                .next()
                .expect("a series line starts with a name");
            assert!(
                declared.iter().any(|d| d == name),
                "series {name} has no preceding # TYPE:\n{text}"
            );
        }
        assert!(!declared.is_empty());
    }

    /// Counters end in `_total` and gauges do not: dashboards and recording
    /// rules key off that suffix.
    #[test]
    fn counter_and_gauge_naming_follows_the_convention() {
        let text = render(&snap());
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("# TYPE ") else {
                continue;
            };
            let (name, kind) = rest.split_once(' ').unwrap();
            match kind {
                "counter" => assert!(name.ends_with("_total"), "counter {name} lacks _total"),
                _ => assert!(!name.ends_with("_total"), "gauge {name} claims _total"),
            }
            assert!(name.starts_with("sipr_"), "{name} is not namespaced");
        }
    }

    /// Durations are exposed in seconds, Prometheus' base unit — the
    /// snapshot carries milliseconds, so this is a real conversion.
    #[test]
    fn durations_are_seconds_not_milliseconds() {
        let text = render(&snap());
        assert!(
            text.contains("sipr_rtd_seconds{rtd=\"1\",stat=\"mean\"} 0.012500"),
            "12.5 ms should be 0.0125 s:\n{text}"
        );
        assert!(text.contains("sipr_rtd_seconds{rtd=\"1\",stat=\"max\"} 0.025000"));
        assert!(!text.contains("_ms"), "no millisecond metric names");
    }

    #[test]
    fn counters_and_labels_carry_the_snapshot() {
        let text = render(&snap());
        assert!(text.contains("sipr_run_info{scenario=\"uac\",role=\"UAC\",display=\"main\"} 1"));
        assert!(text.contains("sipr_calls_created_total 7"));
        assert!(text.contains("sipr_calls_successful_total 5"));
        assert!(text.contains("sipr_calls_failed_total{reason=\"recv_timeout\"} 2"));
        assert!(text.contains("sipr_calls_active 3"));
        assert!(text.contains(
            "sipr_step_messages_total{step=\"0\",label=\"send INVITE\",kind=\"sent\"} 7"
        ));
    }

    /// A scenario name is free text. An unescaped quote would terminate the
    /// label early and corrupt every series after it.
    #[test]
    fn label_values_are_escaped() {
        let mut s = snap();
        s.scenario = "say \"hi\"\\ now\nthen".into();
        let text = render(&s);
        assert!(
            text.contains(r#"scenario="say \"hi\"\\ now\nthen""#),
            "{text}"
        );
        // The escaped newline must not have split the line.
        let info = text
            .lines()
            .find(|l| l.starts_with("sipr_run_info{"))
            .expect("info series");
        assert!(info.ends_with(" 1"), "{info}");
    }

    /// An empty run still exposes every family, so a scrape target does not
    /// have series appear and vanish as traffic starts.
    #[test]
    fn an_empty_snapshot_still_renders() {
        let text = render(&Snapshot::default());
        assert!(text.contains("sipr_calls_created_total 0"));
        assert!(text.contains("sipr_messages_total{kind=\"sent\"} 0"));
        assert!(text.contains("sipr_rtp_packets_total{kind=\"sent\"} 0"));
    }
}
