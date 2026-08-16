//! `sipr-stats`: counters, response-time histograms, repartitions, the
//! statistics CSV, and message/error trace files (milestone M4).
//!
//! The engine's event loop owns a [`StatSet`] and feeds it directly — no
//! locks, per docs/ARCHITECTURE.md ("stats are read from snapshots"). File
//! writers are plain buffered writers owned by the same thread; a load run
//! with `-trace_msg` enabled is expected to pay for its I/O (same as SIPp).
//!
//! CSV format: a pragmatic subset of SIPp's `-trace_stat` columns with
//! SIPp-style `(P)`/`(C)` periodic/cumulative naming, semicolon-separated.
//! Full column parity is a v1-polish item — recorded in SIPP_COMPAT §6.

mod histogram;

pub use histogram::{Histogram, Repartition};

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Everything counted during a run. The engine's `RunReport` is a summary
/// distilled from this at the end.
#[derive(Debug)]
pub struct StatSet {
    /// Run start.
    pub started: Instant,
    /// Calls created by the pacer (UAC side).
    pub outgoing_created: u64,
    /// Calls created from inbound initial requests (UAS side).
    pub incoming_created: u64,
    /// Calls that completed their scenario.
    pub successful: u64,
    /// Failed: unexpected message.
    pub failed_unexpected: u64,
    /// Failed: recv timeout with no ontimeout.
    pub failed_timeout: u64,
    /// Failed: retransmissions exhausted.
    pub failed_retrans: u64,
    /// Failed: everything else (render errors, aborts, global timeout).
    pub failed_other: u64,
    /// First transmissions sent.
    pub messages_sent: u64,
    /// Messages received and matched to a step.
    pub messages_matched: u64,
    /// Retransmissions sent (timer-driven).
    pub retrans_sent: u64,
    /// Inbound retransmissions detected (answered from last response).
    pub retrans_recv: u64,
    /// In-dialog requests answered automatically (`-aa`).
    pub auto_answered: u64,
    /// Inbound that matched no live call / no step.
    pub unexpected: u64,
    /// Datagrams that were not SIP.
    pub garbage: u64,
    /// Response-time stopwatches by RTD name (`"1"`, `"2"`, ...).
    pub rtd: HashMap<String, Histogram>,
    /// Call duration histogram (created → ended).
    pub call_length: Histogram,
    /// `ResponseTimeRepartition` (fed by RTD "1").
    pub response_repartition: Repartition,
    /// `CallLengthRepartition`.
    pub call_length_repartition: Repartition,
    // Snapshot of cumulative values at the last CSV dump, for (P) columns.
    last_dump: PeriodSnapshot,
}

#[derive(Debug, Default, Clone, Copy)]
struct PeriodSnapshot {
    at_elapsed: Duration,
    created: u64,
    successful: u64,
    failed: u64,
}

impl StatSet {
    /// New stat set with the scenario's repartition bounds.
    #[must_use]
    pub fn new(response_bounds: &[u64], call_length_bounds: &[u64]) -> Self {
        Self {
            started: Instant::now(),
            outgoing_created: 0,
            incoming_created: 0,
            successful: 0,
            failed_unexpected: 0,
            failed_timeout: 0,
            failed_retrans: 0,
            failed_other: 0,
            messages_sent: 0,
            messages_matched: 0,
            retrans_sent: 0,
            retrans_recv: 0,
            auto_answered: 0,
            unexpected: 0,
            garbage: 0,
            rtd: HashMap::new(),
            call_length: Histogram::new(),
            response_repartition: Repartition::new(response_bounds),
            call_length_repartition: Repartition::new(call_length_bounds),
            last_dump: PeriodSnapshot::default(),
        }
    }

    /// Total calls created.
    #[must_use]
    pub fn created(&self) -> u64 {
        self.outgoing_created + self.incoming_created
    }

    /// Total failed calls.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.failed_unexpected + self.failed_timeout + self.failed_retrans + self.failed_other
    }

    /// Record an RTD stop for `name`.
    pub fn record_rtd(&mut self, name: &str, d: Duration) {
        self.rtd.entry(name.to_owned()).or_default().record(d);
        if name == "1" {
            self.response_repartition.record(d);
        }
    }

    /// Record a finished call's duration.
    pub fn record_call_length(&mut self, d: Duration) {
        self.call_length.record(d);
        self.call_length_repartition.record(d);
    }

    /// One-line human summary (used by `-bg` and the final report).
    #[must_use]
    pub fn line(&self, live: usize) -> String {
        let rtd1 = self.rtd.get("1");
        let rtd_part = rtd1.map_or_else(String::new, |h| {
            format!(
                " | rtd1 avg {:.1}ms p99 {}ms",
                h.mean_ms(),
                h.percentile_ms(99.0)
            )
        });
        format!(
            "live {live} created {} ok {} failed {} | sent {} matched {} \
             retrans {}/{} unexpected {} garbage {}{rtd_part}",
            self.created(),
            self.successful,
            self.failed(),
            self.messages_sent,
            self.messages_matched,
            self.retrans_sent,
            self.retrans_recv,
            self.unexpected,
            self.garbage,
        )
    }

    /// The CSV header row (write once when creating the file).
    #[must_use]
    pub fn csv_header() -> String {
        "CurrentTime;ElapsedTime(C);ElapsedTime(P);CallRate(P);CallRate(C);\
         IncomingCall(C);OutgoingCall(C);TotalCallCreated;CurrentCall;\
         SuccessfulCall(P);SuccessfulCall(C);FailedCall(P);FailedCall(C);\
         Retransmissions(C);AutoAnswered(C);UnexpectedMessage(C);\
         ResponseTime1(C)ms;ResponseTime1StDev(C)ms;ResponseTime1Max(C)ms;\
         CallLength(C)ms\n"
            .to_owned()
    }

    /// Produce the next CSV row and roll the period snapshot.
    pub fn csv_row(&mut self, live: usize) -> String {
        let elapsed = self.started.elapsed();
        let period = elapsed.saturating_sub(self.last_dump.at_elapsed);
        let period_s = period.as_secs_f64().max(1e-9);
        let created = self.created();
        let d_created = created - self.last_dump.created;
        let d_ok = self.successful - self.last_dump.successful;
        let d_failed = self.failed() - self.last_dump.failed;
        #[allow(clippy::cast_precision_loss)]
        let rate_p = d_created as f64 / period_s;
        #[allow(clippy::cast_precision_loss)]
        let rate_c = created as f64 / elapsed.as_secs_f64().max(1e-9);
        let epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or_default();
        let rtd1 = self.rtd.get("1");
        let (r_avg, r_dev, r_max) =
            rtd1.map_or((0.0, 0.0, 0), |h| (h.mean_ms(), h.stddev_ms(), h.max_ms()));
        self.last_dump = PeriodSnapshot {
            at_elapsed: elapsed,
            created,
            successful: self.successful,
            failed: self.failed(),
        };
        format!(
            "{epoch:.3};{:.3};{:.3};{rate_p:.3};{rate_c:.3};{};{};{created};{live};\
             {d_ok};{};{d_failed};{};{};{};{};{r_avg:.3};{r_dev:.3};{r_max};{:.3}\n",
            elapsed.as_secs_f64(),
            period.as_secs_f64(),
            self.incoming_created,
            self.outgoing_created,
            self.successful,
            self.failed(),
            self.retrans_sent + self.retrans_recv,
            self.auto_answered,
            self.unexpected,
            self.call_length.mean_ms(),
        )
    }
}

/// Buffered line writer for trace files; write failures degrade to a
/// one-time warning rather than killing the run.
pub struct TraceFile {
    writer: Option<std::io::BufWriter<std::fs::File>>,
    path: PathBuf,
}

impl TraceFile {
    /// Create/truncate `path`.
    ///
    /// # Errors
    ///
    /// I/O errors opening the file.
    pub fn create(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            writer: Some(std::io::BufWriter::new(std::fs::File::create(path)?)),
            path: path.to_owned(),
        })
    }

    /// Append a chunk (caller controls framing).
    pub fn write(&mut self, chunk: &str) {
        if let Some(w) = self.writer.as_mut() {
            if w.write_all(chunk.as_bytes()).is_err() {
                eprintln!(
                    "sipr: warning: cannot write {}; tracing disabled",
                    self.path.display()
                );
                self.writer = None;
            }
        }
    }

    /// Flush buffered output (called periodically and at shutdown).
    pub fn flush(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
        }
    }
}

/// Frame one SIP message for `-trace_msg`, SIPp-style separators.
#[must_use]
pub fn frame_message(direction: &str, peer: &str, elapsed: Duration, payload: &[u8]) -> String {
    format!(
        "----------------------------------------------- {:.6}\n{direction} {peer}\n\n{}\n",
        elapsed.as_secs_f64(),
        String::from_utf8_lossy(payload)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_line_render() {
        let mut s = StatSet::new(&[10, 100], &[100, 1000]);
        s.outgoing_created = 10;
        s.successful = 8;
        s.failed_timeout = 2;
        s.record_rtd("1", Duration::from_millis(25));
        s.record_call_length(Duration::from_millis(500));
        assert_eq!(s.created(), 10);
        assert_eq!(s.failed(), 2);
        let line = s.line(3);
        assert!(line.contains("created 10 ok 8 failed 2"), "{line}");
        assert!(line.contains("rtd1 avg 25.0ms"), "{line}");
    }

    #[test]
    fn csv_periods_roll() {
        let mut s = StatSet::new(&[], &[]);
        s.outgoing_created = 5;
        s.successful = 5;
        let header = StatSet::csv_header();
        assert!(header.contains("SuccessfulCall(P);SuccessfulCall(C)"));
        let row1 = s.csv_row(0);
        assert_eq!(row1.matches(';').count(), header.matches(';').count());
        // Second period with no new completions: periodic column reads 0.
        let row2 = s.csv_row(0);
        let cols: Vec<&str> = row2.split(';').collect();
        // SuccessfulCall(P) is column index 9.
        assert_eq!(cols[9], "0", "row2: {row2}");
        assert_eq!(cols[10], "5", "cumulative stays: {row2}");
    }

    #[test]
    fn rtd1_feeds_response_repartition() {
        let mut s = StatSet::new(&[50], &[]);
        s.record_rtd("1", Duration::from_millis(10));
        s.record_rtd("2", Duration::from_millis(500)); // rtd2 must NOT feed it
        let rows = s.response_repartition.rows();
        assert_eq!(rows[0].1 + rows[1].1, 1);
    }

    #[test]
    fn trace_file_writes_and_frames() {
        let dir = std::env::temp_dir().join(format!("sipr-stats-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("trace.log");
        let mut t = TraceFile::create(&path).expect("create");
        t.write(&frame_message(
            "UDP message sent to",
            "127.0.0.1:5060",
            Duration::from_millis(1500),
            b"INVITE sip:x SIP/2.0\r\n",
        ));
        t.flush();
        let content = std::fs::read_to_string(&path).expect("read");
        assert!(content.contains("1.500000"), "{content}");
        assert!(content.contains("INVITE sip:x"), "{content}");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
