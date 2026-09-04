//! RTP streaming from a raw codec file or a test pattern — SIPp's
//! `exec rtp_stream=` (`rtpstream.cpp`).
//!
//! The file is raw codec frames, never decoded: SIPp's only concession is
//! skipping a RIFF/WAVE header when present (its comment: "Doesn't actually
//! parse/convert anything!"), so a 16-bit PCM WAV streamed as PCMA is
//! garbage in both tools. Packets carry a generated 12-byte RTP header
//! (V=2, no marker, sequence from 0, a wall-clock-derived timestamp that
//! advances by `ticks_per_packet`) followed by `bytes_per_packet` file
//! bytes, splicing across the file's end when looping. Pausing does not
//! stop the clock: SIPp fast-forwards the timestamp so the stream "appears
//! up to date" on resume, and so does this.

use std::sync::Arc;

/// SIPp's playback parameters for a payload type + name, from its fixed
/// table in `actions.cpp` `setRTPStreamActInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpParams {
    /// RTP payload type (0..=127).
    pub payload_type: u8,
    /// Payload bytes per packet.
    pub bytes_per_packet: usize,
    /// Packet interval in milliseconds.
    pub ms_per_packet: u64,
    /// RTP timestamp increment per packet.
    pub ticks_per_packet: u32,
    /// Video (`m=video` port, video SSRC) rather than audio.
    pub video: bool,
}

impl RtpParams {
    /// Resolve SIPp's table. `name` is the `payload_name` field; when
    /// absent, the static types 0/8/9/18 get their canonical name (as SIPp
    /// fills in) and anything else is an error, exactly like SIPp.
    ///
    /// # Errors
    ///
    /// The SIPp-worded reason when the type is out of range, unknown, or
    /// its name does not match the table.
    pub fn resolve(payload_type: u8, name: Option<&str>) -> Result<Self, String> {
        if payload_type > 127 {
            return Err(format!(
                "Invalid rtp payload type {payload_type} - cannot set playback parameters"
            ));
        }
        let default_name = match payload_type {
            0 => Some("PCMU/8000"),
            8 => Some("PCMA/8000"),
            9 => Some("G722/8000"),
            18 => Some("G729/8000"),
            _ => None,
        };
        let name = match (name, default_name) {
            (Some(n), _) => n,
            (None, Some(d)) => d,
            (None, None) if payload_type == 13 => "CN/8000",
            (None, None) => {
                return Err("Missing mandatory payload_name parameter in rtp_stream action".into());
            }
        };
        let audio = |bytes, ms, ticks| Self {
            payload_type,
            bytes_per_packet: bytes,
            ms_per_packet: ms,
            ticks_per_packet: ticks,
            video: false,
        };
        match (payload_type, name) {
            (0, "PCMU/8000") | (8, "PCMA/8000") | (9, "G722/8000") => Ok(audio(160, 20, 160)),
            // Comfort noise: SIPp does not check the name.
            (13, _) => Ok(audio(1, 150, 1200)),
            (18, "G729/8000") => Ok(audio(20, 20, 160)),
            (96..=127, "H264/90000") => Ok(Self {
                payload_type,
                bytes_per_packet: 1280,
                ms_per_packet: 160,
                ticks_per_packet: 1280,
                video: true,
            }),
            (96..=127, "iLBC/8000") => Ok(audio(50, 30, 240)),
            (0..=95, _) => Err(format!(
                "Unknown static rtp payload type {payload_type} (name '{name}') - cannot set \
                 playback parameters"
            )),
            _ => Err(format!(
                "Unknown dynamic rtp payload type {payload_type} (name '{name}') - cannot set \
                 playback parameters"
            )),
        }
    }

    /// RTP timestamp ticks per millisecond (integer, as SIPp computes it).
    #[must_use]
    pub fn ticks_per_ms(&self) -> u32 {
        let ms = u32::try_from(self.ms_per_packet).unwrap_or(1).max(1);
        self.ticks_per_packet / ms
    }
}

/// The payload bytes to stream: a file with any RIFF/WAVE header skipped
/// (SIPp `get_wav_header_size` — a header skip, not a decoder).
#[must_use]
pub fn stream_bytes(file: &[u8]) -> Arc<[u8]> {
    Arc::from(&file[wav_header_len(file)..])
}

/// Length of a RIFF/WAVE header up to and including the `data` chunk
/// header, or 0 when `file` is not a WAV.
#[must_use]
pub fn wav_header_len(file: &[u8]) -> usize {
    if file.len() < 12 || &file[0..4] != b"RIFF" || &file[8..12] != b"WAVE" {
        return 0;
    }
    let mut pos = 12;
    while pos + 8 <= file.len() {
        let id = &file[pos..pos + 4];
        let size = u32::from_le_bytes([file[pos + 4], file[pos + 5], file[pos + 6], file[pos + 7]])
            as usize;
        pos += 8;
        if id == b"data" {
            return pos.min(file.len());
        }
        // Chunks are word-aligned.
        pos = pos.saturating_add(size + (size & 1));
    }
    0
}

/// SIPp's RTP-check test patterns: `apattern`/`vpattern` ids 1..=6 fill
/// every packet with one repeated byte.
#[must_use]
pub fn pattern_bytes(pattern_id: u8, bytes_per_packet: usize) -> Option<Arc<[u8]>> {
    let byte = match pattern_id {
        1 => 0xAA,
        2 => 0xBB,
        3 => 0xCC,
        4 => 0xDD,
        5 => 0xEE,
        6 => 0xFF,
        _ => return None,
    };
    Some(Arc::from(vec![byte; bytes_per_packet.max(1)]))
}

/// SIPp's base SSRC (`"CALL"` in hex); each call takes two consecutive ids.
pub const BASE_SSRC: u32 = 0xCA11_0000;

/// A generated RTP stream in flight.
#[derive(Debug)]
pub struct RtpSource {
    data: Arc<[u8]>,
    params: RtpParams,
    cursor: usize,
    /// Loops still to play; `-1` = forever.
    loops_left: i64,
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    /// Packets scheduled so far (sent or skipped while paused).
    ticks: u64,
    paused: bool,
    buf: Vec<u8>,
}

/// What [`RtpSource::next_packet`] produced.
#[derive(Debug, PartialEq, Eq)]
pub enum RtpStep<'a> {
    /// Send these bytes.
    Packet(&'a [u8]),
    /// Paused: nothing to send this interval (the clock advanced).
    Silent,
    /// The loop count is exhausted.
    Done,
}

impl RtpSource {
    /// A stream over `data` with `params`, playing `loops` times (`-1` =
    /// forever), starting at `initial_timestamp`.
    #[must_use]
    pub fn new(
        data: Arc<[u8]>,
        params: RtpParams,
        loops: i64,
        ssrc: u32,
        initial_timestamp: u32,
    ) -> Self {
        Self {
            data,
            params,
            cursor: 0,
            loops_left: loops,
            seq: 0,
            timestamp: initial_timestamp,
            ssrc,
            ticks: 0,
            paused: false,
            buf: Vec::with_capacity(12 + params.bytes_per_packet),
        }
    }

    /// The packet interval.
    #[must_use]
    pub fn interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.params.ms_per_packet)
    }

    /// Packets scheduled so far; packet `n` is due at `start + n * interval`.
    #[must_use]
    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    /// Pause (SIPp `TI_PAUSERTP`): no packets, but the timestamp keeps up.
    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }

    /// Whether the stream is paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Whether this is a video stream (H264 payload).
    #[must_use]
    pub fn is_video(&self) -> bool {
        self.params.video
    }

    /// Advance one interval: build the next packet (or skip it while
    /// paused). The timestamp advances either way.
    pub fn next_packet(&mut self) -> RtpStep<'_> {
        if self.loops_left == 0 || self.data.is_empty() {
            return RtpStep::Done;
        }
        self.ticks += 1;
        let ts = self.timestamp;
        self.timestamp = self.timestamp.wrapping_add(self.params.ticks_per_packet);
        if self.paused {
            return RtpStep::Silent;
        }
        self.buf.clear();
        self.buf.push(0x80);
        self.buf.push(self.params.payload_type & 0x7f);
        self.buf.extend_from_slice(&self.seq.to_be_bytes());
        self.buf.extend_from_slice(&ts.to_be_bytes());
        self.buf.extend_from_slice(&self.ssrc.to_be_bytes());
        self.seq = self.seq.wrapping_add(1);
        // Payload, splicing across the end of the file when looping.
        let mut need = self.params.bytes_per_packet;
        while need > 0 {
            let avail = self.data.len() - self.cursor;
            let take = need.min(avail);
            self.buf
                .extend_from_slice(&self.data[self.cursor..self.cursor + take]);
            self.cursor += take;
            need -= take;
            if self.cursor >= self.data.len() {
                self.cursor = 0;
                if self.loops_left > 0 {
                    self.loops_left -= 1;
                }
                if self.loops_left == 0 {
                    break; // last loop ends here: send the partial packet
                }
            }
        }
        RtpStep::Packet(&self.buf)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn payload_table_matches_sipp() {
        let pcma = RtpParams::resolve(8, None).unwrap();
        assert_eq!(
            (
                pcma.bytes_per_packet,
                pcma.ms_per_packet,
                pcma.ticks_per_packet
            ),
            (160, 20, 160)
        );
        assert!(!pcma.video);
        assert_eq!(pcma.ticks_per_ms(), 8);
        let g729 = RtpParams::resolve(18, Some("G729/8000")).unwrap();
        assert_eq!(g729.bytes_per_packet, 20);
        let ilbc = RtpParams::resolve(98, Some("iLBC/8000")).unwrap();
        assert_eq!(
            (
                ilbc.bytes_per_packet,
                ilbc.ms_per_packet,
                ilbc.ticks_per_packet
            ),
            (50, 30, 240)
        );
        let h264 = RtpParams::resolve(96, Some("H264/90000")).unwrap();
        assert!(h264.video);
        assert_eq!(h264.ms_per_packet, 160);
        let cn = RtpParams::resolve(13, Some("whatever")).unwrap();
        assert_eq!(cn.ms_per_packet, 150);
        assert!(
            RtpParams::resolve(98, None)
                .unwrap_err()
                .contains("Missing mandatory")
        );
        assert!(
            RtpParams::resolve(5, None)
                .unwrap_err()
                .contains("Missing mandatory")
        );
        assert!(
            RtpParams::resolve(5, Some("X/8000"))
                .unwrap_err()
                .contains("Unknown static")
        );
        assert!(
            RtpParams::resolve(100, Some("OPUS/48000"))
                .unwrap_err()
                .contains("Unknown dynamic")
        );
        assert!(
            RtpParams::resolve(200, None)
                .unwrap_err()
                .contains("Invalid")
        );
        // A mismatched name for a static type is an error, as in SIPp.
        assert!(RtpParams::resolve(8, Some("PCMU/8000")).is_err());
    }

    #[test]
    fn wav_header_is_skipped_not_decoded() {
        let mut wav = b"RIFF\x00\x00\x00\x00WAVEfmt ".to_vec();
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend(vec![0u8; 16]);
        wav.extend_from_slice(b"LIST");
        wav.extend_from_slice(&3u32.to_le_bytes());
        wav.extend_from_slice(b"abc\0"); // odd chunk padded
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&4u32.to_le_bytes());
        wav.extend_from_slice(b"\xd5\xd5\xd5\xd5");
        assert_eq!(&*stream_bytes(&wav), b"\xd5\xd5\xd5\xd5");
        assert_eq!(wav_header_len(b"not a wav at all"), 0);
        assert_eq!(&*stream_bytes(b"raw"), b"raw");
    }

    #[test]
    fn patterns_fill_one_byte() {
        assert_eq!(&*pattern_bytes(1, 3).unwrap(), &[0xAA, 0xAA, 0xAA]);
        assert_eq!(&*pattern_bytes(6, 1).unwrap(), &[0xFF]);
        assert!(pattern_bytes(0, 1).is_none());
        assert!(pattern_bytes(7, 1).is_none());
    }

    fn params(bytes: usize) -> RtpParams {
        RtpParams {
            payload_type: 8,
            bytes_per_packet: bytes,
            ms_per_packet: 20,
            ticks_per_packet: 160,
            video: false,
        }
    }

    #[test]
    fn packets_carry_header_and_splice_across_loops() {
        // 5-byte file, 2-byte packets, 2 loops → 10 bytes → 5 packets.
        let data: Arc<[u8]> = Arc::from(&b"abcde"[..]);
        let mut s = RtpSource::new(data, params(2), 2, 0xCA11_0001, 1000);
        let mut payloads = Vec::new();
        loop {
            match s.next_packet() {
                RtpStep::Packet(p) => {
                    assert_eq!(p[0], 0x80);
                    assert_eq!(p[1], 8);
                    assert_eq!(&p[8..12], &0xCA11_0001u32.to_be_bytes());
                    payloads.push((
                        u16::from_be_bytes([p[2], p[3]]),
                        u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
                        p[12..].to_vec(),
                    ));
                }
                RtpStep::Silent => panic!("not paused"),
                RtpStep::Done => break,
            }
        }
        let seqs: Vec<u16> = payloads.iter().map(|p| p.0).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
        let tss: Vec<u32> = payloads.iter().map(|p| p.1).collect();
        assert_eq!(tss, vec![1000, 1160, 1320, 1480, 1640]);
        let bytes: Vec<Vec<u8>> = payloads.iter().map(|p| p.2.clone()).collect();
        assert_eq!(
            bytes,
            vec![
                b"ab".to_vec(),
                b"cd".to_vec(),
                b"ea".to_vec(),
                b"bc".to_vec(),
                b"de".to_vec()
            ]
        );
        assert_eq!(s.ticks(), 5);
    }

    #[test]
    fn infinite_loop_and_pause_fast_forward() {
        let data: Arc<[u8]> = Arc::from(&b"xy"[..]);
        let mut s = RtpSource::new(data, params(2), -1, 1, 0);
        for _ in 0..1000 {
            assert!(matches!(s.next_packet(), RtpStep::Packet(_)));
        }
        s.set_paused(true);
        assert_eq!(s.next_packet(), RtpStep::Silent);
        assert_eq!(s.next_packet(), RtpStep::Silent);
        s.set_paused(false);
        let RtpStep::Packet(p) = s.next_packet() else {
            panic!("resumed")
        };
        // seq continues from 1000 (two skipped intervals sent nothing) but the
        // timestamp jumped by 3 intervals: the clock never paused.
        assert_eq!(u16::from_be_bytes([p[2], p[3]]), 1000);
        assert_eq!(u32::from_be_bytes([p[4], p[5], p[6], p[7]]), 1002 * 160);
    }

    #[test]
    fn empty_data_or_zero_loops_is_done() {
        let mut s = RtpSource::new(Arc::from(&b""[..]), params(2), -1, 1, 0);
        assert_eq!(s.next_packet(), RtpStep::Done);
        let mut s = RtpSource::new(Arc::from(&b"ab"[..]), params(2), 0, 1, 0);
        assert_eq!(s.next_packet(), RtpStep::Done);
    }
}
