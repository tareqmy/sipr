//! `exec play_dtmf="digits[,tone_ms]"`: RFC 4733 telephone-event packets
//! generated in process, as SIPp's `prepare_dtmf` (`prepare_pcap.c`).
//!
//! The output is a synthetic [`PcapStream`] so it replays through the same
//! scheduler and socket as a pcap, which is exactly what SIPp does (it
//! builds a fake `pcap_pkts` and hands it to `send_packets`). Shapes and
//! timing follow SIPp to the millisecond:
//!
//! - a warm-up burst of 20 "noop" packets 20 ms apart (payload type 97, a
//!   4-byte zero body) so NATs open and the peer latches the new SSRC;
//! - per digit `k`, start packets every 20 ms while `cur < tone_ms`, at
//!   `400 + (k+1)*2*tone_ms + cur` ms, marker set on the first only,
//!   `duration = cur * 8`, one RTP timestamp per event;
//! - then three end packets 1 ms apart with the end bit and the full
//!   duration.
//!
//! One deliberate fix: SIPp's warm-up packets step the sequence number by
//! two (both `n_pkts` and `start_seq_no` are incremented while the sequence
//! is their sum), so peers see a 50% loss during the warm-up. sipr numbers
//! them consecutively. The payload type is SIPp's hard-coded 96 (the
//! bundled scenario advertises telephone-event as 101, a mismatch SIPp
//! ships with); pass `payload_type` to fix that per scenario.

use std::time::Duration;

use crate::pcap::{Frame, PcapStream};

/// SIPp's defaults: 200 ms tones, clamped to 50..=2000.
pub const DEFAULT_TONE_MS: u64 = 200;
/// SIPp's hard-coded DTMF payload type.
pub const DEFAULT_PAYLOAD_TYPE: u8 = 96;
const NOOP_PAYLOAD_TYPE: u8 = 97;
const NOOP_PACKETS: u64 = 20;
const PACKET_MS: u64 = 20;
/// SIPp: "RTP timestamp, should be random".
const TIMESTAMP_START: u32 = 24_000;
const VOLUME: u8 = 10;

/// What to generate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtmfRequest {
    /// Digits `0-9 * # A-D`; anything else is skipped (SIPp).
    pub digits: String,
    /// Tone length in ms; out-of-range values fall back to 200 (SIPp).
    pub tone_ms: u64,
    /// RTP payload type for the events (SIPp: always 96).
    pub payload_type: u8,
    /// SSRC for this burst (SIPp: a fresh one per action).
    pub ssrc: u32,
    /// First sequence number (SIPp: per-call counter from 1200).
    pub start_seq: u16,
}

impl DtmfRequest {
    /// Parse SIPp's attribute value `digits[,tone_ms]`.
    #[must_use]
    pub fn parse(value: &str, payload_type: u8, ssrc: u32, start_seq: u16) -> Self {
        let (digits, tone) = match value.split_once(',') {
            Some((d, t)) => (d, t.trim().parse::<u64>().unwrap_or(0)),
            None => (value, DEFAULT_TONE_MS),
        };
        let tone_ms = if (50..=2000).contains(&tone) {
            tone
        } else {
            DEFAULT_TONE_MS
        };
        Self {
            digits: digits.trim().to_owned(),
            tone_ms,
            payload_type,
            ssrc,
            start_seq,
        }
    }
}

/// Generate the packet sequence. Returns the stream and the number of
/// packets (the caller advances its per-call sequence counter by it).
#[must_use]
pub fn generate(req: &DtmfRequest) -> (PcapStream, u16) {
    let mut frames: Vec<Frame> = Vec::new();
    let mut seq = req.start_seq;
    let mut push = |at_ms: u64, marker: bool, pt: u8, ts: u32, body: &[u8]| {
        let mut payload = Vec::with_capacity(12 + body.len());
        payload.push(0x80);
        payload.push((pt & 0x7f) | if marker { 0x80 } else { 0 });
        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend_from_slice(&ts.to_be_bytes());
        payload.extend_from_slice(&req.ssrc.to_be_bytes());
        payload.extend_from_slice(body);
        seq = seq.wrapping_add(1);
        frames.push(Frame {
            offset: Duration::from_millis(at_ms),
            dst_port: 0,
            payload,
        });
    };
    let events: Vec<u8> = req.digits.chars().filter_map(digit_event).collect();
    if events.is_empty() {
        return (PcapStream::default(), 0);
    }
    // Warm-up.
    let mut ts_offset = 0u64;
    for _ in 0..NOOP_PACKETS {
        let ts = TIMESTAMP_START.wrapping_add(u32::try_from(ts_offset).unwrap_or(0));
        push(ts_offset, false, NOOP_PAYLOAD_TYPE, ts, &[0, 0, 0, 0]);
        ts_offset += PACKET_MS;
    }
    let timestamp_start = TIMESTAMP_START.wrapping_add(u32::try_from(ts_offset).unwrap_or(0));
    let tone = req.tone_ms;
    for (k, event) in events.iter().enumerate() {
        let k64 = k as u64;
        let event_ts = timestamp_start.wrapping_add(u32::try_from(k64 * tone * 2).unwrap_or(0));
        let base = ts_offset + (k64 + 1) * tone * 2;
        let mut cur = 0u64;
        let mut first = true;
        while cur < tone {
            let duration = u16::try_from(cur * 8).unwrap_or(u16::MAX);
            let body = [
                *event,
                VOLUME,
                duration.to_be_bytes()[0],
                duration.to_be_bytes()[1],
            ];
            push(base + cur, first, req.payload_type, event_ts, &body);
            first = false;
            cur += PACKET_MS;
        }
        let duration = u16::try_from(tone * 8).unwrap_or(u16::MAX);
        let body = [
            *event,
            0x80 | VOLUME,
            duration.to_be_bytes()[0],
            duration.to_be_bytes()[1],
        ];
        for i in 0..3u64 {
            push(
                base + tone + i + 1,
                false,
                req.payload_type,
                event_ts,
                &body,
            );
        }
    }
    let count = u16::try_from(frames.len()).unwrap_or(u16::MAX);
    (
        PcapStream {
            frames,
            base_port: 0,
            skipped: 0,
            link_type: 0,
        },
        count,
    )
}

/// RFC 4733 event code for a DTMF character (SIPp's map).
fn digit_event(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        '*' => Some(10),
        '#' => Some(11),
        'A' => Some(12),
        'B' => Some(13),
        'C' => Some(14),
        'D' => Some(15),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn req(digits: &str, tone: u64) -> DtmfRequest {
        DtmfRequest {
            digits: digits.into(),
            tone_ms: tone,
            payload_type: 96,
            ssrc: 0x1234_5678,
            start_seq: 1200,
        }
    }

    #[test]
    fn parse_handles_tone_and_clamps() {
        assert_eq!(DtmfRequest::parse("12#", 96, 1, 1200).tone_ms, 200);
        assert_eq!(DtmfRequest::parse("1,100", 96, 1, 1200).tone_ms, 100);
        assert_eq!(DtmfRequest::parse("1,10", 96, 1, 1200).tone_ms, 200);
        assert_eq!(DtmfRequest::parse("1,5000", 96, 1, 1200).tone_ms, 200);
        assert_eq!(DtmfRequest::parse("1,junk", 96, 1, 1200).tone_ms, 200);
        assert_eq!(DtmfRequest::parse(" 1 , 300 ", 96, 1, 1200).digits, "1");
    }

    #[test]
    fn one_digit_has_sipp_shape_and_timing() {
        let (s, n) = generate(&req("5", 200));
        // 20 noop + 10 start (0,20,..,180) + 3 end = 33
        assert_eq!(n, 33);
        assert_eq!(s.len(), 33);
        assert_eq!(s.base_port, 0);
        // Noops: PT 97, no marker, 20 ms apart, 4 zero bytes, ts 24000 + ms.
        for (i, f) in s.frames[..20].iter().enumerate() {
            assert_eq!(f.offset, Duration::from_millis(20 * i as u64));
            assert_eq!(f.payload[1], 97);
            assert_eq!(&f.payload[12..], &[0, 0, 0, 0]);
            let ts = u32::from_be_bytes(f.payload[4..8].try_into().unwrap());
            assert_eq!(ts, 24_000 + 20 * i as u32);
        }
        // Digit starts at 400 + 1*2*200 = 800 ms, marker on the first only.
        let start = &s.frames[20];
        assert_eq!(start.offset, Duration::from_millis(800));
        assert_eq!(start.payload[1], 0x80 | 96);
        assert_eq!(&start.payload[12..], &[5, 10, 0, 0]);
        let second = &s.frames[21];
        assert_eq!(second.offset, Duration::from_millis(820));
        assert_eq!(second.payload[1], 96);
        assert_eq!(&second.payload[12..], &[5, 10, 0, 160]); // duration 20*8
        // Event timestamp constant: 24400 + 0.
        for f in &s.frames[20..] {
            let ts = u32::from_be_bytes(f.payload[4..8].try_into().unwrap());
            assert_eq!(ts, 24_400);
        }
        // Ends: 1 ms apart from 800+200+1, end bit, duration 1600.
        for (i, f) in s.frames[30..].iter().enumerate() {
            assert_eq!(f.offset, Duration::from_millis(1001 + i as u64));
            assert_eq!(&f.payload[12..], &[5, 0x8a, 0x06, 0x40]);
        }
        // Consecutive sequence numbers from 1200 (SIPp's warm-up skips by 2).
        let seqs: Vec<u16> = s
            .frames
            .iter()
            .map(|f| u16::from_be_bytes([f.payload[2], f.payload[3]]))
            .collect();
        assert_eq!(seqs, (1200..1233).collect::<Vec<u16>>());
        assert_eq!(&s.frames[0].payload[8..12], &0x1234_5678u32.to_be_bytes());
    }

    #[test]
    fn digits_are_spaced_two_tones_apart_and_junk_is_skipped() {
        let (s, n) = generate(&req("1x*", 100));
        // per digit: 5 starts + 3 ends = 8; two digits + 20 noops = 36
        assert_eq!(n, 36);
        let d1 = &s.frames[20];
        let d2 = &s.frames[28];
        assert_eq!(d1.offset, Duration::from_millis(400 + 200));
        assert_eq!(d2.offset, Duration::from_millis(400 + 400));
        assert_eq!(d1.payload[12], 1);
        assert_eq!(d2.payload[12], 10); // '*'
        let ts2 = u32::from_be_bytes(d2.payload[4..8].try_into().unwrap());
        assert_eq!(ts2, 24_400 + 200);
        assert!(s.frames.windows(2).all(|w| w[0].offset <= w[1].offset));
    }

    #[test]
    fn no_valid_digits_is_empty() {
        let (s, n) = generate(&req("xyz", 200));
        assert_eq!(n, 0);
        assert!(s.is_empty());
    }
}
